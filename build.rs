fn main() {
    println!("cargo:rerun-if-changed=bpf/xdp_httpd.bpf.c");
    let out = std::env::var("OUT_DIR").unwrap();
    let st = std::process::Command::new("clang")
        .args(["-O2", "-g", "-target", "bpf", "-Wall"])
        .arg(format!("-I/usr/include/{}-linux-gnu", std::env::consts::ARCH))
        .args(["-c", "bpf/xdp_httpd.bpf.c", "-o", &format!("{out}/xdp_httpd.o")])
        .status()
        .expect("clang introuvable");
    assert!(st.success(), "compilation eBPF échouée");
}
