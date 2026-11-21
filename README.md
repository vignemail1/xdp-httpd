# xdp-httpd

Serveur HTTP **statique** minimaliste (mémoire et CPU) fonctionnant au-dessus d'**AF_XDP** :

- un programme **eBPF/XDP** filtre les paquets à la source : seuls l'ARP, l'ICMP et le TCP destinés à l'IP du serveur (ports HTTP / HTTPS) sont redirigés vers le socket AF_XDP ; **tout le reste (SSH…) continue vers le noyau** ;
- une pile TCP/IP en espace utilisateur (**smoltcp**), mono-thread, sans runtime async ni GC ;
- **HTTPS optionnel** via **rustls** (feature Cargo `tls`) ;
- **gros fichiers** : streaming par blocs, fichiers > 4 Gio, requêtes `Range` (reprise de téléchargement, lecture vidéo), `HEAD` ;
- **accès restreint** : seuls les fichiers réguliers du dossier de base sont servis ; tout le reste reçoit une **page de refus personnalisable** (403 par défaut) ;
- **zero-copy** optionnel (`XDP_ZC=1`) avec repli automatique en mode copie.

> ⚠️ Code fourni **sans avoir été compilé ni testé**. Les API de `xsk-rs`, `aya` et `smoltcp` évoluent : les versions sont figées dans `Cargo.toml` et la section [Erreurs de compilation prévisibles](#erreurs-de-compilation-prévisibles) liste les corrections probables.

```
NIC ──► XDP (eBPF)  ─┬─ ARP pour IP_SRV          ─┐
                     ├─ ICMP vers IP_SRV          ├─► XSKMAP ─► AF_XDP ─► smoltcp ─► HTTP / rustls
                     ├─ TCP vers IP_SRV:80 / :443 ┘
                     ├─ autre trafic vers IP_SRV ──► DROP
                     └─ tout le reste (SSH…)      ──► XDP_PASS (noyau)
```

## Arborescence

```
xdp-httpd/
├── Cargo.toml
├── build.rs              # compile bpf/xdp_httpd.bpf.c avec clang
├── bpf/xdp_httpd.bpf.c   # programme XDP (filtre + redirection XSKMAP)
└── src/
    ├── main.rs           # configuration, boucle principale, HTTP/TLS
    ├── dev.rs            # périphérique smoltcp au-dessus d'AF_XDP
    └── http.rs           # parsing requête, Range, MIME, sécurité des chemins, page de refus
```

## Prérequis

### Système
- Linux **≥ 5.10** recommandé (AF_XDP, `bpf_redirect_map` avec action de repli ≥ 5.3, liens BPF ≥ 5.9).
- Droits **root** (ou capacités `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_NET_RAW`, `CAP_SYS_ADMIN` sur noyau ancien).
- Une interface réseau ; pour de vraies performances un pilote AF_XDP natif (i40e, ice, ixgbe, mlx5, igc, virtio_net récent…). Sinon le mode générique (SKB) fonctionne partout.

### Outils de compilation
- **Rust** stable ≥ 1.75 (`rustup`).
- **clang** (compilation eBPF), **pkg-config**, **libxdp** et **libbpf** (utilisées par `xsk-rs`), en-têtes noyau.

Debian / Ubuntu :
```bash
sudo apt install build-essential clang llvm pkg-config libbpf-dev libxdp-dev \
                 linux-libc-dev linux-headers-$(uname -r)
curl https://sh.rustup.rs -sSf | sh
```
Fedora / RHEL :
```bash
sudo dnf install clang llvm pkgconf libbpf-devel libxdp-devel kernel-headers kernel-devel
```
Arch :
```bash
sudo pacman -S clang llvm pkgconf libbpf xdp-tools linux-headers
```

## Compilation

```bash
git clone https://github.com/vignemail1/xdp-httpd.git
cd xdp-httpd

# HTTP seul
cargo build --release

# HTTP + HTTPS (rustls, backend crypto ring)
cargo build --release --features tls
```
Binaire produit : `target/release/xdp-httpd`.

## Exécution

Le serveur possède **sa propre adresse IP**, qui ne doit **pas** être configurée sur l'interface côté noyau (sinon noyau et serveur se disputeraient l'ARP).

| Variable | Obligatoire | Défaut | Rôle |
|---|---|---|---|
| `XDP_IF` | oui | — | interface réseau (ex. `eth0`) |
| `XDP_IP` | oui | — | IP/préfixe du serveur (ex. `192.168.1.50/24`) |
| `XDP_GW` | non | — | passerelle par défaut (clients hors sous-réseau) |
| `XDP_QUEUE` | non | `0` | file RX de la carte liée au socket |
| `XDP_PORT` | non | `80` | port HTTP |
| `XDP_MODE` | non | `auto` | `auto`, `drv` (natif) ou `skb` (générique) |
| `XDP_ZC` | non | `0` | `1` = tentative de zero-copy (mode natif requis ; repli automatique en mode copie) |
| `XDP_RX_CSUM` | non | vérifié | `off` = ne pas vérifier les checksums à la réception (checksums toujours calculés à l'émission) ; à réserver à un réseau fiable |
| `XDP_DENY_FILE` | non | page intégrée | fichier HTML renvoyé pour tout chemin refusé (lu une fois au démarrage) |
| `XDP_DENY_CODE` | non | `403` | code HTTP de la réponse de refus (400–599) |
| `XDP_TLS_CERT` | si TLS | — | certificat PEM (chaîne complète) |
| `XDP_TLS_KEY` | si TLS | — | clé privée PEM (PKCS#8, RSA ou EC) |
| `XDP_TLS_PORT` | non | `443` | port HTTPS |

Argument positionnel : dossier à servir (défaut : dossier courant).

### Politique d'accès et page de refus

Seuls sont servis les **fichiers réguliers situés dans le dossier de base** (un chemin de dossier sert son `index.html` s'il existe). **Tout le reste** reçoit la même réponse de refus, sans distinction, pour ne rien révéler de l'arborescence :

- fichier ou dossier inexistant ;
- tentative de sortie de la racine (`..`, `%2e%2e`, chemin absolu, octet nul) ;
- lien symbolique pointant hors de la racine ;
- dossier sans `index.html`, fichier spécial (socket, périphérique) ou illisible.

Le corps de la réponse est le fichier HTML de `XDP_DENY_FILE` (page minimale intégrée si absent), le code est `XDP_DENY_CODE` (403 par défaut). Pour `HEAD`, seul l'en-tête est envoyé.

```bash
echo '<!doctype html><h1>Interdit</h1>' > /etc/xdp-httpd/403.html
sudo XDP_IF=eth0 XDP_IP=192.168.1.50/24 \
     XDP_DENY_FILE=/etc/xdp-httpd/403.html XDP_DENY_CODE=404 \
     ./target/release/xdp-httpd /srv/www
```

Remarques :
- le fichier de refus peut se trouver **hors** de la racine servie (il n'est lu qu'au démarrage, jamais depuis une requête) ;
- les erreurs de protocole gardent leurs codes propres : `400` (requête invalide), `405` (méthode autre que GET/HEAD), `416` (plage invalide sur un fichier existant) ;
- le démarrage échoue si `XDP_DENY_FILE` est illisible ou si `XDP_DENY_CODE` est hors de 400–599.

### Zero-copy et offload matériel

| Fonction | Support |
|---|---|
| **Zero-copy AF_XDP** (`XDP_ZC=1`) | oui, si le pilote le gère (i40e, ice, ixgbe, mlx5, igc, stmmac) ; force le mode XDP natif ; repli automatique en mode copie avec message |
| **Steering par la carte** (ntuple) | oui, via `ethtool` (voir ci-dessous) |
| **Ignorer la vérification des checksums RX** | oui, `XDP_RX_CSUM=off` |
| **Checksum TX matériel** | non (nécessite `XDP_TX_METADATA`, noyau ≥ 6.8, peu de pilotes ; non exposé par `xsk-rs`) |
| **TSO / GRO** | impossible avec AF_XDP |

Le message de démarrage indique le mode réellement obtenu (`zero-copy` ou `copie`). Même en zero-copy, chaque trame reçue est encore copiée dans un tampon intermédiaire : seule la copie noyau ↔ UMEM est évitée.

```bash
sudo XDP_IF=eth0 XDP_IP=192.168.1.50/24 XDP_ZC=1 ./target/release/xdp-httpd /srv/www
```

### Une seule file RX
Le socket AF_XDP n'écoute qu'**une** file. Deux solutions :

1. réduire la carte à une file :
```bash
sudo ethtool -L eth0 combined 1
```
2. **diriger le trafic du serveur vers la file choisie** avec le tri matériel (ntuple), sans toucher aux autres flux :
```bash
sudo ethtool -K eth0 ntuple on
sudo ethtool -N eth0 flow-type tcp4 dst-ip 192.168.1.50 dst-port 80  action 2
sudo ethtool -N eth0 flow-type tcp4 dst-ip 192.168.1.50 dst-port 443 action 2
sudo XDP_IF=eth0 XDP_IP=192.168.1.50/24 XDP_QUEUE=2 XDP_ZC=1 ./target/release/xdp-httpd /srv/www
```
L'ARP suit le hachage normal de la carte et peut arriver sur une autre file : utilisez une entrée ARP statique côté client ou routeur, ou gardez la solution 1.

### HTTP
```bash
sudo XDP_IF=eth0 XDP_IP=192.168.1.50/24 XDP_GW=192.168.1.1 \
     ./target/release/xdp-httpd /srv/www
```

### HTTPS
```bash
sudo XDP_IF=eth0 XDP_IP=192.168.1.50/24 XDP_GW=192.168.1.1 \
     XDP_TLS_CERT=/etc/ssl/srv/fullchain.pem XDP_TLS_KEY=/etc/ssl/srv/privkey.pem \
     ./target/release/xdp-httpd /srv/www
```
Certificat de test :
```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout key.pem -out cert.pem -days 365 -subj /CN=10.0.0.2 -addext subjectAltName=IP:10.0.0.2
```

### Test local avec une paire veth
```bash
sudo ip link add v0 type veth peer name v1
sudo ip addr add 10.0.0.1/24 dev v0
sudo ip link set v0 up && sudo ip link set v1 up
sudo XDP_IF=v1 XDP_IP=10.0.0.2/24 XDP_MODE=skb ./target/release/xdp-httpd .

curl -v http://10.0.0.2/
curl -r 1000-1999 -o part.bin http://10.0.0.2/gros.iso      # Range
curl -k https://10.0.0.2/                                     # si --features tls
curl -i http://10.0.0.2/../etc/passwd                         # => page de refus
curl -i http://10.0.0.2/inexistant                            # => même page de refus
```

### Arrêt / nettoyage
`Ctrl-C` suffit : le programme XDP est détaché automatiquement à la fin du processus (lien BPF). Si un programme restait attaché (noyau ancien, crash) :
```bash
sudo ip link set dev eth0 xdp off      # ou xdpgeneric off
```

## Empreinte et réglages

Constantes en tête de `src/main.rs` :

| Constante | Défaut | Effet |
|---|---|---|
| `FRAMES` | 4096 | UMEM = FRAMES × 4 Kio = 16 Mio (2048 → 8 Mio) |
| `RX_FRAMES` | 2048 | trames réservées à la réception |
| `MAX_CONN` | 32 | connexions simultanées par port |
| `TX_BUF` | 128 Kio | tampon d'émission TCP par connexion (débit des gros fichiers) |
| `RX_BUF` | 8 Kio | tampon de réception TCP par connexion |

CPU au repos ≈ 0 : la boucle dort dans `poll()` jusqu'au prochain paquet ou timer TCP.

Limites connues : une connexion = une requête (`Connection: close`), pas de listing de répertoire (sert `index.html`), IPv4 uniquement, pas de TSO ni d'offload de checksum TX (smoltcp calcule les checksums en logiciel). Le corps de la page de refus est envoyé d'un bloc : gardez-le petit (quelques Kio).

## Erreurs de compilation prévisibles

| Symptôme | Cause | Correction |
|---|---|---|
| `clang introuvable` (panic dans `build.rs`) | clang absent | `apt install clang llvm` |
| `fatal error: 'asm/types.h' file not found` | chemin des en-têtes multi-arch | `apt install linux-libc-dev` (et `gcc-multilib` si besoin) ; sinon adapter le `-I/usr/include/<arch>-linux-gnu` dans `build.rs` |
| `'bpf/bpf_helpers.h' file not found` | libbpf-dev absent | `apt install libbpf-dev` |
| `Unable to find libclang` / `bindgen` échoue (build de `libxdp-sys`) | libclang absent | `apt install libclang-dev` ; ou `export LIBCLANG_PATH=/usr/lib/llvm-XX/lib` |
| `could not find system library 'libxdp'` / `libbpf` | paquets -dev ou pkg-config absents | `apt install libxdp-dev libbpf-dev pkg-config` ; vérifier `pkg-config --libs libxdp` |
| `no method named data_mut` / `cursor` / `contents` sur `Umem`/`Data` | API `xsk-rs` différente de la 0.6 | garder `xsk-rs = "=0.6.x"` ou adapter `src/dev.rs` selon `cargo doc --open` |
| `call to unsafe function ... requires unsafe block` ou `unused_unsafe` | fonction `xsk-rs` sûre/non sûre selon version | ajouter/retirer le bloc `unsafe { }` concerné |
| `the trait AsRawFd is not implemented for Fd` | `xsk-rs` n'expose pas `AsRawFd` | utiliser la méthode équivalente (`fd.as_raw_fd()` / `fd.fd()`) dans `main.rs` |
| `no function or associated item named set_global` / signature `XskMap::set` | API `aya` ≠ 0.13 | figer `aya = "=0.13.1"` ; en 0.12 `EbpfLoader` s'appelle `BpfLoader` et `Ebpf` → `Bpf` |
| `expected Ipv4Addr, found Address` / `as_bytes` introuvable | smoltcp ≥ 0.12 (adresses = `core::net`) | figer `smoltcp = "=0.11.0"` ou remplacer `as_bytes()` par `octets()` |
| `no field max_burst_size` | version smoltcp | supprimer la ligne dans `dev.rs` |
| erreurs `rustls_pemfile` / `with_single_cert` | versions rustls ↔ pemfile incompatibles | rustls 0.23 + rustls-pemfile 2.x ensemble |
| `ring` : `failed to run custom build command` | compilateur C absent | `apt install build-essential` |
| `XDP_ZEROCOPY` / `XDP_COPY` introuvable dans `BindFlags` | nom différent selon la version de `xsk-rs` | consulter `cargo doc --open` et adapter `sock_cfg()` dans `main.rs` |
| `the ? operator can only be applied ... String` sur `Deny::load(...)?` | `Box<dyn Error>` n'accepte pas `String` via `?` dans votre contexte | remplacer par `.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?` |

## Erreurs d'exécution prévisibles

| Symptôme | Cause | Correction |
|---|---|---|
| `Operation not permitted` | pas root / capacités manquantes | `sudo`, ou `setcap cap_net_admin,cap_net_raw,cap_bpf,cap_sys_admin+ep` |
| `failed to attach` / `Operation not supported` en mode natif | pilote sans XDP natif | `XDP_MODE=skb` |
| `Device or resource busy` | un autre programme XDP est attaché | `ip link set dev eth0 xdp off` |
| Aucun paquet reçu | trafic sur une autre file RX | `ethtool -L eth0 combined 1`, `XDP_QUEUE=n` ou règle ntuple |
| Le serveur ne répond pas à l'ARP / répond mal | IP aussi configurée côté noyau, ou ARP reçu sur une autre file | `ip addr del <IP> dev eth0` ; vérifier la file (voir « Une seule file RX ») |
| `Cannot allocate memory` à la création UMEM | limite memlock (noyau < 5.11) | `ulimit -l unlimited` |
| `zero-copy refusé (...), repli en mode copie` | pilote sans zero-copy (`EOPNOTSUPP`) | comportement normal : le serveur continue en mode copie ; sinon utiliser un pilote compatible |
| `ethtool -N` : `Operation not supported` | carte sans tri ntuple | `ethtool -L eth0 combined 1` |
| Erreur rustls `aucune clé privée trouvée` | clé chiffrée ou format inconnu | `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key8.pem` |
| Vérifieur eBPF rejette le programme | noyau trop ancien | noyau ≥ 5.10 |
| `erreur: XDP_DENY_FILE <chemin>: No such file or directory` | fichier de refus introuvable ou illisible | vérifier le chemin (absolu recommandé) et les droits de lecture du compte qui lance le serveur |
| `erreur: XDP_DENY_CODE=200 invalide (attendu 400-599)` | code hors plage d'erreur | utiliser un code entre 400 et 599 |
| La page de refus s'affiche pour un fichier qui existe | fichier hors racine (lien symbolique sortant), droits insuffisants ou chemin avec `..` | vérifier `readlink -f` du fichier : il doit rester sous le dossier de base |
