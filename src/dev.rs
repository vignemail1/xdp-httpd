//! Périphérique smoltcp au-dessus d'un socket AF_XDP (xsk-rs 0.6).
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::io::Write;
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, TxQueue, Umem};

pub struct XdpDev {
    pub umem: Umem,
    pub rx: RxQueue,
    pub tx: TxQueue,
    pub fq: FillQueue,
    pub cq: CompQueue,
    pub rx_descs: Vec<FrameDesc>,
    pub tx_free: Vec<FrameDesc>,
    pub scratch: Vec<FrameDesc>,
    pub rx_buf: Vec<u8>,
}

pub struct XRx<'a>(&'a mut [u8]);
pub struct XTx<'a> {
    umem: &'a Umem,
    tx: &'a mut TxQueue,
    free: &'a mut Vec<FrameDesc>,
}

impl RxToken for XRx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
        f(self.0)
    }
}

impl TxToken for XTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = [0u8; 1514];
        let r = f(&mut buf[..len]);
        if let Some(mut d) = self.free.pop() {
            unsafe {
                let mut data = self.umem.data_mut(&mut d);
                let _ = data.cursor().write_all(&buf[..len]);
            }
            // produce_and_wakeup : réveille le noyau seulement si nécessaire
            let n = unsafe { self.tx.produce_and_wakeup(std::slice::from_ref(&d)) }.unwrap_or(0);
            if n == 0 {
                self.free.push(d); // anneau plein : trame perdue, TCP retransmettra
            }
        }
        r
    }
}

impl XdpDev {
    /// Récupère les trames TX dont l'émission est terminée.
    pub fn reclaim(&mut self) {
        let n = unsafe { self.cq.consume(&mut self.scratch) };
        self.tx_free.extend_from_slice(&self.scratch[..n]);
    }
}

impl Device for XdpDev {
    type RxToken<'a> = XRx<'a>;
    type TxToken<'a> = XTx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(XRx<'_>, XTx<'_>)> {
        if self.tx_free.is_empty() {
            self.reclaim();
        }
        if self.tx_free.is_empty() {
            return None;
        }
        let n = unsafe { self.rx.consume(&mut self.rx_descs[..1]) };
        if n == 0 {
            return None;
        }
        let d = self.rx_descs[0];
        let len = unsafe {
            let data = self.umem.data(&d);
            let c = data.contents();
            let l = c.len().min(self.rx_buf.len());
            self.rx_buf[..l].copy_from_slice(&c[..l]);
            l
        };
        // rend immédiatement la trame au noyau
        unsafe { self.fq.produce(std::slice::from_ref(&d)) };
        Some((
            XRx(&mut self.rx_buf[..len]),
            XTx { umem: &self.umem, tx: &mut self.tx, free: &mut self.tx_free },
        ))
    }

    fn transmit(&mut self, _: Instant) -> Option<XTx<'_>> {
        if self.tx_free.is_empty() {
            self.reclaim();
        }
        if self.tx_free.is_empty() {
            return None;
        }
        Some(XTx { umem: &self.umem, tx: &mut self.tx, free: &mut self.tx_free })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = 1514;
        c.max_burst_size = Some(64);
        c
    }
}
