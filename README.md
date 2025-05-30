# VPS-LNbits with WireGuard VPN
_An alternative Documentation to setup LNbits on a VPS, connected to your Lightning Network Node through a secured tunnel_

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/0/0b/Brenner_Base_Tunnel_Aicha-Mauls.jpg/640px-Brenner_Base_Tunnel_Aicha-Mauls.jpg" alt="Brennerbasistunnel – Wikipedia"/>

This guide offers a straightforward approach to setting up LNbits on a Virtual Private Server (VPS), securely connected to your Lightning Network Node via a WireGuard VPN tunnel. It's an alternative to [another guide using OpenVPN](https://github.com/TrezorHannes/vps-lnbits).

You might be looking into this because you:
- Have a dynamic IP from your Internet Service Provider.
- Want to hide your home IP for privacy.
- Aim for faster Lightning Node HTLC routing with Clearnet availability alongside Tor.
- Wish to offer LN Services (LNBits, BTCPay Server, etc.) to others.
- Need a domain name or a free dynamic DNS for your LNBits instance.
- Are curious and want to enhance your technical skills.

## Table of Content

- [Pre-Amble](#pre-amble)
  - [Objective](#objective)
  - [Challenge](#challenge)
  - [Proposed Solution](#proposed-solution)
- [Pre-Reads](#pre-reads)
- [Pre-Requisites](#pre-requisites)
- [Preparations](#preparations)
  - [Make notes](#make-notes)
  - [Visualize](#visualize)
  - [Secure](#secure)
- [Let's get started (LFG!)](#lets-get-started-lfg)
  - [Lightning Node](#lightning-node)
  - [VPS: Setup](#vps-setup)
  - [VPS: Connect to your VPS and tighten it up](#vps-connect-to-your-vps-and-tighten-it-up)
  - [VPS: Install Wireguard](#vps-install-wireguard)
    - [VPS: Firewall](#vps-firewall)
    - [VPS: LND and LNBits Port-Forwarding](#vps-lnd-and-lnbits-port-forwarding)
    - [VPS: Start your WireGuard Server](#vps-start-your-wireguard-server)
  - [VPS: Install LNBits](#vps-install-lnbits)
- [Into the Tunnel](#into-the-tunnel)
  - [LND Node: Install and test the VPN Tunnel](#lnd-node-install-and-test-the-vpn-tunnel)
  - [LND Node: LND adjustments to listen and channel via VPS VPN Tunnel](#lnd-node-lnd-adjustments-to-listen-and-channel-via-vps-vpn-tunnel)
- [Connect VPS LNBits to your LND Node](#connect-vps-lnbits-to-your-lnd-node)
  - [LND Node: provide your VPS LNBits instance read / write access to your LND Wallet](#lnd-node-provide-your-vps-lnbits-instance-read--write-access-to-your-lnd-wallet)
  - [VPS: Customize and configure LNBits to connect to your LNDRestWallet](#vps-customize-and-configure-lnbits-to-connect-to-your-lndrestwallet)
  - [VPS: Start LNBits and test the LND Node wallet connection](#vps-start-lnbits-and-test-the-lnd-node-wallet-connection)
  - [Your domain, Webserver and SSL setup](#your-domain-webserver-and-ssl-setup)
    - [Domain](#domain)
    - [VPS Webserver Option 1: Caddy 🆕 ](#-vps-caddy-web-server)
    - [VPS Webserver Option 2: NGINX](#vps-nginx-web-server)
- [Appendix & FAQ](#appendix--faq)


## Pre-Amble

### Objective
To have your [LNbits](https://github.com/lnbits/lnbits) instance on a cost-effective, anonymous [Virtual Private Server (VPS)](https://www.webcentral.com.au/blog/what-does-vps-stand-for), connected to your self-hosted [Lightning-Network](https://github.com/lightningnetwork/lnd) Node operating in Hybrid-Mode (Tor and Clearnet).

### Challenge
Achieving fast, reliable, non-custodial Bitcoin payments while maintaining privacy can be complex. While LNbits offers easy setup on platforms like Raspiblitz or Umbrel, a custom setup involves navigating several technical steps.

### Proposed Solution
This guide details _one specific method_ to achieve this. Take your time; it might take 1-2 hours depending on your technical proficiency.

## Pre-Reads
This guide builds upon the work of others. Familiarize yourself with these resources for a deeper understanding:
- [Hybrid-Mode for LND](https://github.com/blckbx/lnd-hybrid-mode)
- [Expose server behind NAT with WireGuard and a VPS](https://golb.hplar.ch/2019/01/expose-server-vpn.html)
- [How To Set Up WireGuard on Ubuntu 22.04](https://www.digitalocean.com/community/tutorials/how-to-set-up-wireguard-on-ubuntu-22-04)
- [Official LNbits Installation Guide](https://docs.lnbits.org/guide/installation.html)

## Pre-Requisites
- A running Lightning Node (e.g., `lnd-0.14.2-beta` or newer) on Umbrel (pre-0.5), Raspiblitz, MyNode, or a RaspiBolt.
- Basic command-line skills.
- A domain name or a subdomain from a service like [DuckDNS](https://www.duckdns.org/).
- SSH access to your node and the VPS. For Windows, tools like [PuTTY](https://www.putty.org/) and [PuTTYgen](https://www.ssh.com/academy/ssh/putty/windows/puttygen) are useful.
- A VPS account from a provider like DigitalOcean or any other that offers a public IP.

[![DigitalOcean Referral Badge](https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg)](https://www.digitalocean.com/?refcode=5742b053ef6d&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge)
_Disclaimer: This is a referral link. You get $100 in credit over 60 days. The setup here uses a basic $5-6/month VPS._

## Preparations

### Make notes
Document your steps and configurations. This will be invaluable for future reference or troubleshooting.
- [ ] IP Addresses: VPS external, VPS Tunnel, Node Tunnel
- [ ] Ports for forwarding
- [ ] To-Do list
- [ ] Questions / Open items

### Visualize
A simple diagram can help clarify the connections and data flow.
![High-lvl-Flowchart](https://github.com/TrezorHannes/vps-lnbits-wg/blob/main/Wireguard%20VPN_LNBits.drawio.png?raw=true)

### Secure
This guide does not cover comprehensive security hardening. Always prioritize security: start with small amounts of funds, stay updated on security practices, consider a peer review, and use 2FA/hardware keys where possible.

## Let's get started (LFG!)

### Lightning Node
Assume your Lightning Node is operational, connected via Tor, funded, and you have SSH access with administrative rights.

### VPS: Setup
If you need a VPS, consider [DigitalOcean](https://m.do.co/c/5742b053ef6d) or alternatives that offer a static IP and suit your budget (some even accept Lightning payments).

For DigitalOcean Droplet creation:
   - Create a new Droplet.
   - OS: Ubuntu 20.04 (LTS) x64 or newer.
   - Plan: Basic Shared CPU (e.g., "Regular Intel with SSD" for ~$5-6/month).
   - Datacenter Region: Your choice.
   - Authentication: SSH keys (recommended). Follow DigitalOcean's guide to add your public key.
   - Hostname: A memorable name, e.g., `myLNBits-VPS`.
   - Optional: Backups, Monitoring, IPv6 (not used in this guide).

Once created, note down your VPS's public IPv4 address (e.g., `VPS Public IP: 207.154.241.101`).

### VPS: Connect to your VPS and tighten it up
SSH into your VPS: `ssh root@YOUR_VPS_PUBLIC_IP`.
Perform initial server setup and hardening:
   - Update packages: `sudo apt update && sudo apt upgrade -y`
   - [Create a new sudo user](https://www.digitalocean.com/community/tutorials/initial-server-setup-with-ubuntu-22-04) (e.g., `admin`) and disable root login. Log in as this new user for subsequent steps.
   - Install and configure UFW (Uncomplicated Firewall):
```bash
sudo apt install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp comment 'Standard Webserver HTTP'
sudo ufw allow 443/tcp comment 'SSL Webserver HTTPS'
sudo ufw allow 9735/tcp comment 'LND Main Node 1 Peer Port'
# Add other necessary ports, e.g., for WireGuard (later)
sudo ufw enable
```
   - Install Fail2ban for SSH protection: `sudo apt install fail2ban -y`
   - Follow additional hardening steps from the DigitalOcean initial server setup guide, especially regarding SSH key authentication and securing shared memory if applicable.

### VPS: Install Wireguard
Follow the [DigitalOcean WireGuard setup guide](https://www.digitalocean.com/community/tutorials/how-to-set-up-wireguard-on-ubuntu-22-04) for detailed context. We'll skip IPv6 for simplicity.
   - Install WireGuard: `sudo apt install wireguard -y`
   - Generate keys:
```bash
wg genkey | sudo tee /etc/wireguard/private.key
sudo chmod go= /etc/wireguard/private.key
sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key
```
     Note down the private and public keys.
   - Choose a private IP range for the VPN (e.g., `10.8.0.0/24`). Assign `10.8.0.1` to the VPS.
   - Create WireGuard configuration file `sudo nano /etc/wireguard/wg0.conf`:
```ini
[Interface]
PrivateKey = YOUR_VPS_WIREGUARD_PRIVATE_KEY
Address = 10.8.0.1/24
ListenPort = 51820
SaveConfig = true
```
     Replace `YOUR_VPS_WIREGUARD_PRIVATE_KEY` with the content of `/etc/wireguard/private.key`.
   - Enable IP forwarding: `sudo nano /etc/sysctl.conf`, uncomment `net.ipv4.ip_forward=1`. Save and apply: `sudo sysctl -p`.

#### VPS: Firewall
Configure packet forwarding for WireGuard.
   - Identify your VPS's main network interface (e.g., `eth0`): `ip route list default`
   - Add forwarding rules to `sudo nano /etc/wireguard/wg0.conf` (append these lines):
```ini
PostUp = ufw route allow in on wg0 out on YOUR_MAIN_INTERFACE
PostUp = iptables -t nat -I POSTROUTING -o YOUR_MAIN_INTERFACE -j MASQUERADE
PreDown = ufw route delete allow in on wg0 out on YOUR_MAIN_INTERFACE
PreDown = iptables -t nat -D POSTROUTING -o YOUR_MAIN_INTERFACE -j MASQUERADE
```
     Replace `YOUR_MAIN_INTERFACE` with your actual interface name (e.g., `eth0`). Save the file.
   - Allow WireGuard UDP port through UFW: `sudo ufw allow 51820/udp`

#### VPS: LND and LNBits Port-Forwarding
Forward LND peer traffic and LNBits traffic from the VPS to your node via the tunnel. LNBits will run on port 5000 on the VPS itself, so we primarily focus on LND peer port forwarding here. The LNBits connection to LND will happen over the tunnel directly.
   - Assumption: Your LND node listens on port `9735`. Verify in your `lnd.conf`.
   - Add iptables rules for LND port forwarding (replace `YOUR_MAIN_INTERFACE`, `10.8.0.2` is your LND node's future VPN IP):
```bash
# LND Peer Port Forwarding (e.g., 9735)
sudo iptables -P FORWARD DROP # Default drop, be careful
sudo iptables -A FORWARD -i YOUR_MAIN_INTERFACE -o wg0 -p tcp --syn --dport 9735 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -i YOUR_MAIN_INTERFACE -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i wg0 -o YOUR_MAIN_INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A PREROUTING -i YOUR_MAIN_INTERFACE -p tcp --dport 9735 -j DNAT --to-destination 10.8.0.2:9735
sudo iptables -t nat -A POSTROUTING -o wg0 -p tcp --dport 9735 -d 10.8.0.2 -j SNAT --to-source 10.8.0.1
```
   - **Critical Reminder**: If you adjust ports or forward additional ones, ensure your Node's firewall also permits these incoming connections through its `wg0` interface.
   - **Best Practice for SSH**: Limit SSH access to your home IP: `sudo ufw allow from YOUR_HOME_IP/24 to any port 22 proto tcp comment 'SSH from Home'`. Test login from another terminal before disconnecting.
   - Refresh UFW: `sudo ufw disable && sudo ufw enable`. Check status: `sudo ufw status verbose`.

   To make iptables rules persistent across reboots (more robust than `netfilter-persistent` for complex rules alongside UFW):
   Create a script to save rules: `sudo nano /etc/wireguard/iptables-save.sh`
```bash
#!/bin/bash
# Save current iptables rules
sudo iptables-save > /etc/wireguard/iptables.rules
# If using IPv6:
# sudo ip6tables-save > /etc/wireguard/ip6tables.rules
```
   Make it executable: `sudo chmod +x /etc/wireguard/iptables-save.sh`
   Save current rules (after verifying they work!): `sudo /etc/wireguard/iptables-save.sh`

   Create a systemd service to restore rules at boot: `sudo nano /etc/systemd/system/iptables-restore.service`
```ini
[Unit]
Description=Restore iptables rules
After=network.target
Before=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/wireguard/iptables.rules
# If using IPv6:
# ExecStart=/sbin/ip6tables-restore /etc/wireguard/ip6tables.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```
   Enable the service: `sudo systemctl enable iptables-restore.service`

#### VPS: Start your WireGuard Server
   - Enable and start the WireGuard service:
```bash
sudo systemctl enable wg-quick@wg0.service
sudo systemctl start wg-quick@wg0.service
sudo systemctl status wg-quick@wg0.service
```
Your VPS WireGuard server is now running. Note down:
   - [ ] VPS WireGuard IP (should be `10.8.0.1`)
   - [ ] VPS WireGuard Listen Port (`51820`)
   - [ ] VPS WireGuard Public Key (`cat /etc/wireguard/public.key`)

### VPS: Install LNBits
We'll install LNBits using Poetry, as recommended in the [official LNbits documentation](https://docs.lnbits.org/guide/installation.html#option-2-poetry-recommended-for-developers).
   - Ensure you have Python 3.9 or higher (Python 3.12 is recommended by LNbits at the time of writing). Check with `python3 --version`. Install if necessary (refer to deadsnakes PPA for Ubuntu if needed, or use your system's package manager).
```bash
# Example for Python 3.9 if not present (adjust version as needed)
# sudo apt update
# sudo apt install software-properties-common -y
# sudo add-apt-repository ppa:deadsnakes/ppa
# sudo apt install python3.9 python3.9-distutils -y
```
   - Install Poetry:
```bash
curl -sSL https://install.python-poetry.org | python3 -
export PATH="/home/YOUR_SUDO_USER/.local/bin:$PATH" 
# Add the export line to your ~/.bashrc or ~/.zshrc and source it (source ~/.bashrc)
# Replace YOUR_SUDO_USER with your actual username (e.g., admin)
```
   - Clone LNbits and install dependencies:
```bash
git clone https://github.com/lnbits/lnbits.git # Or lnbits-legend if you prefer the older UI
cd lnbits # Or lnbits-legend
poetry env use python3.9 # Or your installed Python 3.x version, e.g., python3.12
poetry install --only main # Installs only main dependencies
# poetry run python build.py # This step might be deprecated, check LNbits docs. Usually not needed for basic install.

mkdir data
cp .env.example .env
```
   - Test run LNBits (you'll configure it later): `poetry run lnbits --port 5000`
   - Stop it with `CTRL+C`. We'll configure and run it as a service later.
   - For troubleshooting, refer to the [LNbits installation guide](https://docs.lnbits.org/guide/installation.html).

## Into the Tunnel

### LND Node: Install and test the VPN Tunnel
Switch to your Lightning Node's terminal.
   - Install WireGuard and resolvconf:
```bash
sudo apt update
sudo apt install wireguard resolvconf -y
```
   - Generate keys for the node:
```bash
wg genkey | sudo tee /etc/wireguard/private.key
sudo chmod go= /etc/wireguard/private.key
sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key
```
     Note your node's private key (keep secret!) and public key (will be needed on the VPS).
   - Create `wg0.conf` on your node: `sudo nano /etc/wireguard/wg0.conf`. This node will be `10.8.0.2`.
```ini
[Interface]
PrivateKey = YOUR_NODE_WIREGUARD_PRIVATE_KEY
Address = 10.8.0.2/24
# DNS = VPS_DNS_SERVER_1 VPS_DNS_SERVER_2 # Optional: Use VPS DNS, e.g. 67.207.67.2 67.207.67.3 if your VPS provider has them, or common ones like 1.1.1.1

[Peer]
PublicKey = YOUR_VPS_WIREGUARD_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0 # Route all traffic through VPN
Endpoint = YOUR_VPS_PUBLIC_IP:51820
PersistentKeepalive = 25
```
     Replace placeholders with your actual keys and IPs.
   - **Important for LAN access**: To maintain access to your node from your local network while all other traffic goes through the VPN:
     - Find your node's LAN IP (e.g., `192.168.1.100`) and its gateway (e.g., `192.168.1.1`).
     - Find your main network interface (e.g., `eth0`).
     - Add `PostUp` and `PreDown` rules to your node's `/etc/wireguard/wg0.conf` in the `[Interface]` section:
```ini
# Add these lines in [Interface] section of node's wg0.conf
# Replace with your actual Node LAN IP and Gateway IP
PostUp = ip rule add from YOUR_NODE_LAN_IP table 200
PostUp = ip route add default via YOUR_NODE_GATEWAY_IP dev YOUR_NODE_LAN_INTERFACE table 200
PreDown = ip rule delete from YOUR_NODE_LAN_IP table 200
PreDown = ip route delete default via YOUR_NODE_GATEWAY_IP dev YOUR_NODE_LAN_INTERFACE table 200
```

   - On your **VPS terminal**, add your node as a peer:
```bash
sudo wg set wg0 peer YOUR_NODE_WIREGUARD_PUBLIC_KEY allowed-ips 10.8.0.2
sudo wg # Verify the peer is added
```
   - **Test the tunnel on your LND Node**:
     - `sudo wg-quick up wg0`
     - `sudo wg` (check for handshake and traffic on both node and VPS)
     - Test connectivity: `ping 10.8.0.1` (from node to VPS tunnel IP)
     - Check external IP: `curl https://api.ipify.org` (should show VPS IP)
     - Deactivate: `sudo wg-quick down wg0`
   - Enable and start WireGuard service on the node:
```bash
sudo systemctl enable wg-quick@wg0.service
sudo systemctl start wg-quick@wg0.service
sudo systemctl status wg-quick@wg0.service
```

### LND Node: LND adjustments to listen and channel via VPS VPN Tunnel
Back on your LND Node terminal. **Backup your `lnd.conf` before editing!** (e.g., `cp ~/.lnd/lnd.conf ~/.lnd/lnd.conf.bak`). Path may vary based on your node setup (e.g. `/mnt/hdd/lnd/lnd.conf` for Raspiblitz).

Edit `lnd.conf`:
```ini
[Application Options]
externalip=YOUR_VPS_PUBLIC_IP:9735 # Use your VPS Public IP and LND peer port
nat=false
tlsextraip=10.8.0.2 # LND Node's WireGuard IP, for LNbits to connect

[tor]
tor.active=true
tor.v3=true
tor.streamisolation=false
tor.skip-proxy-for-clearnet-targets=true # Enable hybrid mode
```
   - Adjust paths and settings based on your specific LND node software (Raspiblitz, Umbrel, myNode, etc.). Some systems might have scripts that overwrite `lnd.conf`; consult their documentation. For example, Raspiblitz might require changes in `/mnt/hdd/raspiblitz.conf` or specific scripts.
   - Restart LND to apply changes (e.g., `sudo systemctl restart lnd` or Docker restart command for Umbrel).
   - Check LND logs for errors.
   - Verify with `lncli getinfo`. You should see URIs for both your Tor address and your `VPS_PUBLIC_IP:9735`.

## Connect VPS LNBits to your LND Node

### LND Node: provide your VPS LNBits instance read / write access to your LND Wallet
LNBits needs `tls.cert` and `admin.macaroon` from your LND node.
**Warning**: These files are sensitive. Transfer them securely.
1.  **`tls.cert`**: This file updates after LND restarts with the new `tlsextraip`. Check its modification date (`ls -la ~/.lnd/tls.cert`).
    On your **VPS**:
```bash
mkdir -p /home/YOUR_SUDO_USER/.lnd # Or any secure location for LNBits to access
# Securely copy tls.cert from your LND node to the VPS. Example using scp over the tunnel:
# On VPS: scp YOUR_NODE_USER@10.8.0.2:/home/YOUR_NODE_USER/.lnd/tls.cert /home/YOUR_SUDO_USER/.lnd/tls.cert
# Ensure YOUR_SUDO_USER (e.g., admin) owns the file on the VPS and has read access.
# Adjust paths as per your node and VPS user.
chmod 600 /home/YOUR_SUDO_USER/.lnd/tls.cert
```

2.  **`admin.macaroon`**:
    On your **LND Node**:
```bash
xxd -ps -u -c 1000 ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
```
    Copy the long hex string output.

### VPS: Customize and configure LNBits to connect to your LNDRestWallet
On your **VPS** terminal, the initial LNBits configuration involves setting up the data folder and enabling the Admin UI. Edit the LNBits `.env` file: `nano ~/lnbits/.env` (or `~/lnbits-legend/.env`)

#### Initial .env adjustments:
```ini
LNBITS_DATA_FOLDER="/home/YOUR_SUDO_USER/lnbits/data" # Absolute path for LNbits data
LNBITS_ADMIN_UI=true # Enables the Admin User Interface
```
Replace `YOUR_SUDO_USER` with your actual username (e.g., admin). Save the `.env` file.

With these settings, LNbits will start, and the Admin UI will be accessible. The crucial step of connecting LNbits to your LND node (by setting it as the funding source) is done **via the Admin UI** by the super user.

To activate, configure the funding source, and use the Admin UI:
1.  Ensure `LNBITS_ADMIN_UI=true` and `LNBITS_DATA_FOLDER` are correctly set in your `.env` file.
2.  Start LNBits (e.g., `poetry run lnbits` or via its systemd service as configured previously).
3.  The first time LNBits runs with `LNBITS_ADMIN_UI=true`, a super user is automatically created. The Super User ID can typically be found in the `data/.super_user` file within your LNbits data folder (e.g., `cat /home/YOUR_SUDO_USER/lnbits/data/.super_user`).
4.  Access your super user account by appending `?usr=SUPER_USER_ID` to your LNbits domain (e.g., `https://yourdomain.duckdns.org/wallet?usr=YOUR_SUPER_USER_ID`).
5.  Navigate to the "Manage Server" or "Admin" section. Here, you can:
    *   Set the `Funding Source` to `LndRestWallet`.
    *   Provide the necessary LND connection details:
        *   `LND REST Endpoint`: `https://10.8.0.2:8080` (Your LND Node's WireGuard IP and LND REST port)
        *   `LND TLS Certificate Path`: `/home/YOUR_SUDO_USER/.lnd/tls.cert` (Absolute path to `tls.cert` on the VPS that LNBits can access)
        *   `LND Macaroon Path or Hex`: Path to your `admin.macaroon` (ensure LNBits can access it) or the hex-encoded macaroon string. Using the hex string directly is often simpler if the file path access is complex.
    *   Configure other site settings, themes, user permissions, and manage extensions.

For detailed information on the Admin UI, its features, how to manage super users, admin users, and specifically how to set up funding sources, please refer to the [official LNbits Admin UI documentation](https://docs.lnbits.org/guide/admin_ui.html) and the [Backend Wallets documentation](https://docs.lnbits.org/guide/wallets.html).

### VPS: Start LNBits and test the LND Node wallet connection
Run LNBits as a systemd service for auto-start and restarts.
Create `sudo nano /etc/systemd/system/lnbits.service`:
```ini
[Unit]
Description=LNbits
After=network.target wg-quick@wg0.service # Ensure network and VPN are up

[Service]
WorkingDirectory=/home/YOUR_SUDO_USER/lnbits # Adjust path to your lnbits directory
ExecStart=/home/YOUR_SUDO_USER/.local/bin/poetry run lnbits --port 5000
User=YOUR_SUDO_USER # Your non-root sudo user
Restart=always
TimeoutSec=120
RestartSec=30
Environment="PYTHONUNBUFFERED=1" # Add other environment vars if needed directly here or ensure .env is read

[Install]
WantedBy=multi-user.target
```
Replace `YOUR_SUDO_USER` and paths.
Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable lnbits.service
sudo systemctl start lnbits.service
sudo systemctl status lnbits.service
```
Check logs: `sudo journalctl -u lnbits.service -f`
If successful, LNBits should connect to your LND node. You can test the connection from VPS to LND REST API:
`curl https://10.8.0.2:8080/v1/balance --cacert /home/YOUR_SUDO_USER/.lnd/tls.cert --header "Grpc-Metadata-macaroon: YOUR_HEX_ENCODED_ADMIN_MACAROON"`
(This command syntax might vary slightly, it's for conceptual testing).

LNBits should be running on `http://YOUR_VPS_PUBLIC_IP:5000` or `http://127.0.0.1:5000` locally on the VPS.

### Your domain, Webserver and SSL setup
To make LNBits accessible via a domain with HTTPS.

#### Domain
Use a service like [DuckDNS](https://www.duckdns.org/) for a free subdomain or any domain registrar.
   - Create an account (e.g., DuckDNS).
   - Add a subdomain (e.g., `paymeinsats.duckdns.org`).
   - Point this subdomain (A record) to your `VPS Public IP`.
   - Note your DuckDNS token if using Nginx with Certbot's DNS challenge.

Choose Caddy (simpler) or Nginx as your webserver.

#### 🆕 VPS: Caddy web server
Caddy handles HTTPS automatically.
<details><summary>Click here to expand Caddy setup</summary>
<p>

##### Check DNS
Ensure your domain points to your VPS IP using [DNS Lookup](https://mxtoolbox.com/DNSLookup.aspx) or [whatsmydns.net](https://www.whatsmydns.net/).

##### Install Caddy
(Refer to [official Caddy installation docs](https://caddyserver.com/docs/install) for the latest instructions for your OS)
```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy -y
```

##### Create Caddyfile
`sudo nano /etc/caddy/Caddyfile`
Replace `yourdomain.duckdns.org` with your actual domain:
```caddyfile
yourdomain.duckdns.org {
  reverse_proxy /* 127.0.0.1:5000 {
    # Optional: If you experience issues with SSE (Server-Sent Events) like live updates in LNbits,
    # you might need specific handling for SSE paths, but usually the above is enough.
    # header_up X-Forwarded-Host {host} # Caddy v2 often handles this automatically
  }
}
```
For Server-Sent Events (SSE) used by some LNbits extensions (like live payment updates), a more specific configuration might be needed if issues arise:
```caddyfile
yourdomain.duckdns.org {
    # Handle Server-Sent Events separately for better keepalive/buffering control
    handle /api/v1/payments/sse* {
        reverse_proxy 127.0.0.1:5000 {
            transport http {
                keepalive off # Or adjust as needed
                compression off # SSE streams might not benefit from compression
            }
        }
    }

    # Default reverse proxy for all other requests
    reverse_proxy /* 127.0.0.1:5000
}
```


##### Start Caddy
```bash
sudo systemctl enable caddy
sudo systemctl start caddy
sudo systemctl status caddy
```
Caddy will automatically obtain and renew SSL certificates.
</p>
</details>

#### VPS: Nginx web server
<details><summary>Click here to expand Nginx setup</summary>
<p>

##### SSL Certificate with Certbot
Using Certbot with Nginx plugin:
```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d yourdomain.duckdns.org
```
Follow the prompts. Certbot will obtain the certificate and configure Nginx for SSL.

Alternatively, for DNS challenge (useful for wildcards or if port 80 is blocked):
```bash
sudo apt install certbot -y # Or snap install if preferred
# For DuckDNS, you might need a plugin like certbot-dns-duckdns.
# Example for manual DNS challenge:
# sudo certbot certonly --manual --preferred-challenges dns -d yourdomain.duckdns.org
# Follow instructions to add TXT records to your DNS.
```

##### Nginx Configuration
If Certbot didn't create/update it, or for manual setup:
`sudo nano /etc/nginx/sites-available/yourdomain.conf`
```nginx
server {
    listen 80;
    server_name yourdomain.duckdns.org;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.duckdns.org;

    ssl_certificate /etc/letsencrypt/live/yourdomain.duckdns.org/fullchain.pem; # Path from Certbot
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.duckdns.org/privkey.pem; # Path from Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # Recommended SSL options
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # Recommended DH params

    access_log /var/log/nginx/yourdomain-access.log;
    error_log /var/log/nginx/yourdomain-error.log;

    location / {
        proxy_pass http://127.0.0.1:5000; # LNbits local address
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed by LNbits extensions)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```
Replace `yourdomain.duckdns.org` with your actual domain.
Enable the site and restart Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/yourdomain.conf /etc/nginx/sites-enabled/
sudo nginx -t # Test configuration
sudo systemctl restart nginx
```
</p>
</details>

Now the moment of truth: Go to your Website [https://yourdomain.duckdns.org](https://yourdomain.duckdns.org) and either celebrate 🍻 
or troubleshoot where things could have gone wrong. If the former: Congratulations - you made it!

Hope you enjoyed this article. Please do share feedback and suggestions for improvement.
If this guide was of any help, I'd appreciate if you share the article with others, give me a follow on X [![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/HandsdownI.svg?style=social&label=Follow%20%40HodlmeTight1337)](https://twitter.com/HodlmeTight1337) or [nostr](https://njump.me/npub1ch25m5lkk8kfepr63f0jnpd9te8l9f585pfpr2g2ma4pre9rmlrqlu0yjy), perhaps even donating some sats to hakuna@hodlmetight.org or via [Getalby](https://getalby.com/p/hakuna).

I'm also always grateful for incoming channels to my node: [HODLmeTight](https://amboss.space/node/037f66e84e38fc2787d578599dfe1fcb7b71f9de4fb1e453c5ab85c05f5ce8c2e3)

## Appendix & FAQ

#### How do I restrict who can create wallets on my LNBits?
After creating your admin user wallet in LNBits, note the user ID from the URL (e.g., `/usermanager/?usr=[32-digit-user-ID]`).
Edit `~/lnbits/.env` and add the ID(s) to `LNBITS_ALLOWED_USERS`:
`LNBITS_ALLOWED_USERS="USER_ID_1,USER_ID_2"`
Restart LNBits service.

#### I'm stuck. Who can help?
First, check logs (`journalctl -u lnbits.service`, Nginx/Caddy logs, LND logs). If the issue persists, create a detailed issue on the [LNbits GitHub](https://github.com/lnbits/lnbits/issues) or relevant community forums. Do not share macaroons or private keys.

#### What can I do with LNBits?
Explore the [LNBits website](https://lnbits.com/) and its extensions for various use cases like donation pages, payment solutions, etc.

#### Why DigitalOcean? Can I use a more private/Lightning-payable VPS?
This guide uses DigitalOcean for familiarity. Providers like [Luna Node](https://www.lunanode.com/) accept sats and are often cheaper. Feel free to adapt this guide for other VPS providers.

#### Can I connect multiple LND nodes to the same VPS tunnel?
Yes. Each node will need a unique WireGuard peer IP (e.g., `10.8.0.3`, `10.8.0.4`) and a unique LND peer port (e.g., 9736, 9737). You'll need to:
- Add peer configurations on the VPS WireGuard server for each new node.
- Add corresponding iptables DNAT/SNAT rules on the VPS for each node's LND peer port.
- Configure each LND node's `lnd.conf` with its unique `externalip` (VPS public IP + unique LND port) and `tlsextraip` (its unique WireGuard IP).
- Adjust LNbits `.env` files if running multiple LNBits instances, or configure a single LNBits to manage multiple LND backends if supported (check LNbits documentation for advanced multi-backend setups).

---
Hope this guide helps! Share feedback or suggestions for improvement. If it helped, consider sharing it or supporting the original author/projects.
