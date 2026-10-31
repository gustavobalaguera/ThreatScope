# ThreatScope - Threat Intelligence Enrichment 
I created a zero-database SOC environment on a free Oracle Cloud instance to familiarize myself with both offensive and defensive sides of network and cloud defense strategies. I really enjoyed this project as I got to learn more about what I love while simultaneously giving back to the cyber community by reporting all malicious IPs to **AbuseIPDB**. Below are the parts I followed throughout this project. ***Note, these notes should not be followed blindly as I include mistakes I made and how I mitigated them.*** 

Check out the website here: [ThreatScope | Live Threat Intelligence Dashboard](https://soc.gb-resu.me/)

*Disclaimer: AI was used in the generation of this README.md file based on my personal notes*

### Overview

For the sensor tier, I deployed the Suricata NIDS for network detection, OWASP Coraza WAF for web exploits, and Cowrie as an interactive SSH honeypot. 

To handle the ever increasing telemetry with the server's limited memory, I engineered an asynchronous Python state engine. It tracks byte-offsets in SQLite, deduplicates events using SHA-256 hashing, and handles log rotations seamlessly. I chose SQLite over a heavy database daemon because it provides embedded, ACID-compliant state persistence without the background RAM overhead. 

By pairing OS inode tracking with byte-offset seeking and SHA-256 deduplication, I was able to create a stateless Python collector that processes raw threat telemetry in milliseconds while maintaining data accuracy across server restarts and log rotations. Additionally, rather than using a heavy traditional database API, the collector performs atomic POSIX file writes (`os.replace`) to a static JSON file, which allows the NGINX reverse proxy to serve live attack metrics to a custom React 19 dashboard with near zero latency and zero race conditions.


## TechStack
<div align="center">
<pre>
┌─────────────────────────────────────────────────────────────────────────┐
│                        FRONTEND & DASHBOARD LAYER                       │
├─────────────────────────────────────────────────────────────────────────┤
│  • Framework & Runtime: TanStack Start v1 | React 19 | Bun | Vite       │
│  • Styling: Tailwind CSS v4                                             │
│  • State & Data Fetching: TanStack Query (@tanstack/react-query)        │
│  • Visualizations: Cobe 3D Globe (WebGL) | Recharts | SVG Maps          |
|  • Made with help from Lovable                                          │
└────────────────────────────────────┬────────────────────────────────────┘
│
                             ▼ (HTTP / static JSON polling)
┌─────────────────────────────────────────────────────────────────────────┐
│                        WEB SERVING & PROXY TIER                         │
├─────────────────────────────────────────────────────────────────────────┤
│  • Reverse Proxy & Static File Server: NGINX                            │
│  • Published Outputs: /api/metrics.json | /api/ips.txt                  │
└────────────────────────────────────▲────────────────────────────────────┘
│
                         │ (POSIX atomic file swap)
┌────────────────────────────────────┴────────────────────────────────────┐
│                  TELEMETRY PROCESSING & STATE ENGINE                    │
├─────────────────────────────────────────────────────────────────────────┤
│  • Processing Runtime: Python 3 (update_metrics.py)                     │
│  • Embedded State Store: SQLite (state.sqlite3 in WAL Mode)             │
│  • Concurrency Locking: Linux flock                                     │
│  • Deduplication: SHA-256 Hashing & Primary Key Constraints             │
│  • Geolocation DB: MaxMind GeoLite2-City (.mmdb)                        │
└────────────────────────────────────▲────────────────────────────────────┘
│
                                │ (Raw Log Streams & Docker Logs)
┌────────────────────────────────────┴────────────────────────────────────┐
│                          SECURITY SENSOR ARRAY                          │
├─────────────────────────────────────────────────────────────────────────┤
│  • Network NIDS: Suricata 7 (ET Open Ruleset)                           │
│  • Web Application Firewall: Coraza WAF (Caddy + OWASP CRS 4.x)         │
│  • Decoy Deception: Cowrie SSH/Telnet Honeypot                          │
│  • Host IPS: Fail2ban                                                   │
│  • Centralized SIEM: Wazuh SIEM / OpenSearch                            │
└────────────────────────────────────▲────────────────────────────────────┘
│
┌────────────────────────────────────┴────────────────────────────────────┐
│                       CLOUD INFRASTRUCTURE HOST                         │
├─────────────────────────────────────────────────────────────────────────┤
│  • Provider & Operating System: Oracle Cloud Infrastructure (OCI)       │
│    Ubuntu 22.04 LTS (ARM64/aarch64)                                     │
│  • Network Interface: Primary NIC enp0s6                                │
└─────────────────────────────────────────────────────────────────────────┘
</pre>
</div>
 
# Part 1: OCI Infrastructure Provisioning, Network Hardening & Out-of-Band Lockout Recovery

This section details the baseline infrastructure deployment on Oracle Cloud Infrastructure (OCI), the architectural rationale for migrating administrative management off standard ports, and the step-by-step resolution of a dual-layer firewall lockout using OCI's out-of-band serial console.


## 1. Cloud Instance Specifications & Initial Provisioning

### Compute & Network Baseline
* **Cloud Provider**: Oracle Cloud Infrastructure (OCI)
* **Operating System**: Ubuntu 22.04 LTS (Canonical)
* **Instance Shape**: `VM.Standard.A1.Flex` (Ampere ARM, 2 OCPUs, 12 GB RAM) or `VM.Standard2.1` (AMD x86)
* **Virtual Cloud Network (VCN)**: Public Subnet with attached Internet Gateway
* **Primary Interface**: `enp0s6` (bound to Public IP)



## 2. Rebinding Host SSH Daemon (`sshd`) to Custom Port 

### Architectural Rationale
In order to capture authentic SSH brute-force attempts from internet threat actors, I rebinded the host's actual ssh daemon to a custom port and set up the **Cowrie Honeypot** to  listen on standard **TCP Port 22**. 

### Step-by-Step Configuration Commands (Do NOT blindly follow)

1. **Create a Backup of the Original SSH Configuration**:
   ```bash
   sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig
   ```

2. **Modify the Listening Port in `sshd_config`**:
   ```bash
   # Update port assignment from 22
   sudo sed -i 's/#Port 22/Custom Port/' /etc/ssh/sshd_config
   sudo sed -i 's/Port 22/Custom Port/' /etc/ssh/sshd_config

   # Ensure password authentication is disabled in favor of keypairs
   sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
   sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
   ```

3. **Validate Configuration Syntax**:
   ```bash
   # Test sshd configuration for syntax errors prior to restart
   sudo sshd -t
   ```

4. **Restart the SSH Service**:
   ```bash
   sudo systemctl restart sshd
   ```


## 3. Major Technical Blocker: Dual-Layer Firewall Lockout

### Incident Description
Immediately after restarting `sshd` and closing the existing terminal session, remote admin access failed completely across all ports:

```bash
ssh -p <custom port> -i ~/.ssh/oci_threatscope_key.key ubuntu@<OCI_PUBLIC_IP>
# Result: ssh: connect to host <OCI_PUBLIC_IP> port <custom port>: Connection timed out
```

### Root Cause Analysis: Dual-Firewall Policy Collision
The management connection failure was caused by two distinct, non-communicating firewall layers running simultaneously:

```text
[ Incoming SSH Request ]
                 │
                 ▼
 ┌───────────────────────────────┐
 │ Layer 1: OCI VCN Security List│ ──► [DROPPED: Ingress rule only allowed Port 22]
 └───────────────┬───────────────┘
                 │ (If allowed)
                 ▼
 ┌───────────────────────────────┐
 │ Layer 2: Host OS iptables     │ ──► [REJECTED: Default rule position 6 dropped non-whitelisted ports]
 └───────────────────────────────┘
```

1. **Layer 1 (Cloud Edge / VCN Security List)**: Oracle Cloud’s default Virtual Cloud Network Security List only included an ingress permit rule for destination TCP Port 22. Packets targeted at my custom port were silently dropped at the cloud infrastructure perimeter.
2. **Layer 2 (Host Kernel / `iptables`)**: OCI Ubuntu images ship with pre-loaded `iptables` rules containing an explicit `REJECT` target at the bottom of the `INPUT` chain. Even if a packet bypassed the VCN firewall, the local OS dropped traffic on my custom port because no explicit rule accepted it higher up in the chain.

So yes, I blocked myself out of my own web server... 

## 4. Out-of-Band Emergency Recovery & Firewall Synchronization

Since remote network access was completely severed on all ports and standard OCI Ubuntu cloud images do not ship with a default password for the `ubuntu` user, standard serial console login prompts (`secops-gateway-vnic login:`) reject unauthenticated TTY logins. Recovery required launching an **Out-of-Band (OOB) Serial Console Connection**, interrupting the GRUB bootloader, and booting directly into an emergency root shell to reset user credentials and repair host firewall rules.

### Step 1: Establish OCI Cloud Shell Serial Console
1. Log into the **OCI Web Console**.
2. Navigate to **Compute** → **Instances** → Select your compute node (`secops-gateway-vnic`).
3. Scroll down to **Resources** (bottom left) and select **Console Connections**.
4. Click **Launch Cloud Shell Connection** to open an interactive web terminal session attached to the instance's virtual serial port (`ttyAMA0`).

### Step 2: GRUB Interception & Emergency Root Shell Boot
Since password authentication for local TTY is not set out of the box, you have to bypass the standard init process:

1. Issue a **Reboot** command for the instance from the OCI Web Console while keeping the Cloud Shell terminal open.
2. In the Cloud Shell terminal, select the **Ubuntu** boot device from the UEFI menu and tap `Esc` to interrupt standard loading and drop into the GRUB boot menu or CLI prompt.
3. Locate the active kernel image and root volume UUID (`ls /boot` and `probe -u $root`).
4. Edit the primary Ubuntu boot entry, appending `rw init=/bin/bash` to the line starting with `vmlinuz-*-oracle` to override the default systemd init sequence.
5. Press `Ctrl+X` or `F10` to boot directly into a passwordless root shell:
   ```bash
   root@(none):/#
   ```

### Step 3: Account Password Assignment & Daemon Workspace Repair
From inside the emergency root shell, set a password for the `ubuntu` user and fix volatile runtime directories bypassed during single-user initialization:

```bash
# Set a new local password for the ubuntu account
passwd ubuntu

# Re-create the SSH privilege separation directory if missing after reboot
mkdir -p /run/sshd

# Complete system initialization or reboot into normal runlevel
exec /sbin/init
```

Once the standard login prompt (`secops-gateway-vnic login:`) appears, authenticate using `ubuntu` and the newly created password.

### Step 4: Repair Host `iptables` & Persist Kernel Rules
Once authenticated inside the host shell, insert an explicit `ACCEPT` rule at **position 1** of the `INPUT` chain (before any trailing `REJECT` rules) to permit traffic on custom SSH port:

```bash
# Insert ACCEPT rule at line 1 in the INPUT chain
sudo iptables -I INPUT 1 -p tcp -m state --state NEW -m tcp --dport <custom port> -j ACCEPT

# Save rules persistently to survive future reboots
sudo netfilter-persistent save
sudo netfilter-persistent reload

# Confirm rule 1 is active
sudo iptables -L INPUT -n -v --line-numbers
```

### Step 5: Configure Cloud Subnet VCN Ingress Rules
1. In the OCI Web Console, navigate to **Networking** → **Virtual Cloud Networks**.
2. Select your VCN → Click **Security Lists** → Open **Default Security List for Public Subnet**.
3. Click **Add Ingress Rules** and configure:
   * **Source Type**: CIDR
   * **Source CIDR**: `0.0.0.0/0`
   * **IP Protocol**: TCP
   * **Source Port Range**: All
   * **Destination Port Range**: `<custom port>`
   * **Description**: `Administrative SSH Daemon (sshd)`
4. Click **Add Ingress Rules**.

### Step 6: Verification of Remote Administrative Access
Return to the local machine terminal and verify SSH connectivity over custom port:

```bash
ssh -p <custom port> -i ~/.ssh/oci_threatscope_key.key ubuntu@<OCI_PUBLIC_IP>
```

## 5. Summary State & Readiness Checklist

At the completion of Part 1, the cloud host environment meets the following baseline conditions:

| Component | Port | Status | Function |
| :--- | :--- | :--- | :--- |
| **Host OS** | N/A | Ubuntu 22.04 LTS Active | Primary Compute Infrastructure |
| **Administrative SSH** | `<custom port>` | Bound & Permitted | Secure Remote Management |
| **Port 22** | `22` | Isolated & Unbound | Reserved for Cowrie Honeypot Redirection |
| **Firewall (Host)** | `iptables` | Rule saved via `netfilter-persistent` | Kernel-level ingress filter |
| **Firewall (Cloud)** | OCI VCN | Ingress `<custom port>` Allowed | Edge-level ingress filter |

# Part 2: Multi-Layer Security Sensor Deployment, Network Topology & Sensor Troubleshooting

This section provides a detailed guide to installing, configuring, routing, and troubleshooting the multi-layered defensive sensor stack: **Suricata 7 NIDS**, **Coraza WAF (and latest OWASP CRS)**, **Cowrie Honeypot**, and **Fail2ban IPS**, along with SIEM integration via **Wazuh**.

## 1. System Sensor Architecture & Port Routing Matrix

Each security sensor operates in isolation, capturing attacks across distinct network OSI layers without interfering with host management or frontend web traffic.

```text
                                 [ PUBLIC INTERNET TRAFFIC ]
                                              │
         ┌────────────────────────────────────┼────────────────────────────────────┐
         │ (TCP 80/443 -> 8081)               │ (TCP 22 -> 2222)                   │ (Host NIC: enp0s6)
         ▼                                    ▼                                    ▼
┌──────────────────┐                 ┌──────────────────┐                 ┌──────────────────┐
│   Coraza WAF     │                 │ Cowrie Honeypot  │                 │  Suricata NIDS   │
│ (Caddy + CRS 4)  │                 │  (Decoy SSH/Tel) │                 │(Promiscuous Sniff)│
└────────┬─────────┘                 └────────┬─────────┘                 └────────┬─────────┘
         │                                    │                                    │
   Docker stderr                        cowrie.json                              eve.json
         │                                    │                                    │
         └────────────────────────────────────┼────────────────────────────────────┘
                                              │
                                              ▼
                             [ Telemetry Collection Engine ]
```

### Sensor Port Topology Matrix

| Sensor | Daemon / Environment | External Port | Internal Port | Log Destination | Primary Function |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Suricata 7** | Host Native (`systemd`) | Promiscuous | `enp0s6` | `/var/log/suricata/eve.json` | L3/L4 Network Packet Sniffing & ET Open Ruleset Signatures |
| **Coraza WAF** | Docker (`coraza-waf`) | `8081` (Internal) | `8081` | Container `stderr` / Docker Logs | L7 HTTP/S Web Application Firewall (SQLi, XSS, Path Traversal) |
| **Cowrie** | User Sandbox (`cowrie`) | `22` | `2222` | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` | Decoy SSH/Telnet Brute-Force & Command Execution Capture |
| **Fail2ban** | Host Native (`systemd`) | `<custom port>` | `<custom port>` | Host `SYSLOG` / `journald` | Active Host Protection & Dynamic `iptables` Banning |
| **Wazuh SIEM**| Container / Package | `4443` | `4443` | `/var/ossec/logs/alerts/alerts.json` | Centralized Security Event Correlation & Dashboarding |

---

## 2. Suricata 7 NIDS Installation & Configuration

I had Suricata operate in passive promiscuous mode on the primary network interface (`enp0s6`), inspecting unencrypted network packets against the Emerging Threats (ET) Open ruleset.

<!-- ### Step 1: Add Repository & Install Suricata
```bash
# Add official Suricata stable PPA
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt-get update

# Install Suricata and jq for log parsing
sudo apt-get install -y suricata jq
```

### Step 2: Configure Network Interface & EVE JSON Output
Edit `/etc/suricata/suricata.yaml` to set primary NIC and enable structured `eve.json` logging:

```bash
# Set default network interface variable to enp0s6
sudo sed -i 's/interface: eth0/interface: enp0s6/g' /etc/suricata/suricata.yaml

# Confirm eve-log JSON output is enabled in /etc/suricata/suricata.yaml
sudo suricata-update
```

Verify that the `af-packet` section in `/etc/suricata/suricata.yaml` specifies `enp0s6`:

```yaml
af-packet:
  - interface: enp0s6
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

### Step 3: Fetch Rules & Manage Service Lifecycle
```bash
# Download the latest Emerging Threats (ET) Open ruleset
sudo suricata-update

# Test configuration syntax
sudo suricata -T -c /etc/suricata/suricata.yaml

# Enable and start Suricata systemd service
sudo systemctl enable suricata
sudo systemctl restart suricata

# Verify live JSON log generation
sudo tail -f /var/log/suricata/eve.json | jq .
``` -->

## 3. Coraza WAF (OWASP Core Rule Set) via Docker

Coraza WAF runs inside a containerized Caddy web server using the latest OWASP CRS rules to detect and block web layer attacks (SQL Injection, Cross-Site Scripting, Remote Code Execution).

<!-- ### Step 1: Install Docker & Docker Compose
```bash
# Install Docker prerequisites
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

# Add Docker's official GPG key and repository
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL [suspicious link removed] | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] [suspicious link removed] \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add ubuntu user to docker group
sudo usermod -aG docker ubuntu
```

### Step 2: Deploy Coraza WAF Container
To prevent port collisions with NGINX (which owns public Ports 80 and 443), map the Coraza container's HTTP port to internal **Port 8081**:

```bash
# Create directory for Coraza configuration
mkdir -p ~/coraza-waf && cd ~/coraza-waf

# Launch Coraza Caddy container bound to internal port 8081
docker run -d \
  --name coraza-waf \
  --restart always \
  -p 127.0.0.1:8081:80 \
  corazawaf/coraza-caddy:latest
```

### Step 3: Test Web Attack Detection
Simulate a SQL Injection attempt against the WAF endpoint:

```bash
# Send malicious SQLi request to Coraza WAF
curl -i "[suspicious link removed]"

# Expected Response: HTTP/1.1 403 Forbidden
``` -->

### Technical Blocker: The Invisible Docker `stderr` Capture Bug
* **Problem**: Coraza successfully blocked attack traffic with `403 Forbidden`, but the telemetry script reported 0 WAF blocks. I ran into this issue much later once actually coding the script but decided to include it here.
* **Root Cause**: Caddy/Coraza outputs security warning logs (`WAF rule violation detected`) to `stderr` rather than `stdout`. Standard `subprocess.Popen` or `docker logs` execution without stream merging captured an empty string.
* **Resolution**: Reconfigured Python collection scripts and shell subprocess wrappers to merge `stderr` into `stdout`:
  ```python
  # Python subprocess stream merging fix
  process = subprocess.Popen(
      ["docker", "logs", "--since", f"{since_ts}s", "coraza-waf"],
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,  # Merges stderr into stdout stream
      text=True
  )
  ```

## 4. Cowrie SSH/Telnet Honeypot Deployment

Cowrie is a medium-interaction honeypot designed to log SSH/Telnet brute-force attacks, credential usage, and interactive shell commands. I've captured tens of thousands of commands and login attempts from this tool alone, proving to be an amazing tool to include in this project.

<!-- ### Step 1: Create Unprivileged User & Set Up Virtual Environment
```bash
# Create isolated cowrie system user
sudo useradd -m -s /bin/bash cowrie
sudo su - cowrie

# Install dependencies and clone repository
git clone [suspicious link removed] ~/cowrie
cd ~/cowrie

# Set up Python virtual environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: Configure Cowrie Environment
Create custom configuration in `~/cowrie/etc/cowrie.cfg`:

```ini
[honeypot]
hostname = secops-prod-01
log_path = var/log/cowrie

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = false
```

### Step 3: Start Cowrie & Configure Kernel Port Forwarding
Exit back to the `ubuntu` administrative user and configure `iptables` to silently redirect incoming traffic on standard **Port 22** to Cowrie’s internal listening port **2222**:

```bash
# Exit cowrie user back to ubuntu
exit

# Start Cowrie daemon as cowrie user
sudo -u cowrie /home/cowrie/cowrie/bin/cowrie start

# Redirect incoming Port 22 traffic to Port 2222 via PREROUTING NAT
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Save NAT iptables rule persistently
sudo netfilter-persistent save
```

### Step 4: Verify Honeypot Log Generation
Test the decoy SSH endpoint from an external host or local shell:

```bash
# Attempt login to Honeypot on Port 22
ssh root@127.0.0.1 -p 22

# Inspect structured JSON log output
sudo tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json | jq .
``` -->


## 5. Fail2ban IPS Configuration & SYSLOG Standardization

Fail2ban is set up protects the administrative SSH daemon by dynamically injecting drop rules into `iptables` when authentication failure thresholds are exceeded. I don't expect to see much activity from here but I've configured it to uphold strict rules to ban any IPs attempting to login with a password indefinitely as I use a private key instead. 

<!-- ### Step 1: Install & Configure Fail2ban Jail
```bash
# Install Fail2ban
sudo apt-get install -y fail2ban

# Create local jail configuration
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

Edit `/etc/fail2ban/jail.local` to monitor custom SSH :

```ini
[sshd]
enabled  = true
port     = <custom port>
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = 3
findtime = 600
bantime  = 3600
``` -->

## 6. Wazuh SIEM Integration & Port Binding Resolution

Wazuh provides centralized log aggregation, security monitoring, and rule correlation across all deployed sensors.

<!-- ### Step 1: Wazuh All-in-One Deployment
Deploy the single-node Wazuh indexer, manager, and dashboard components using the official installer:

```bash
# Download and execute Wazuh installation script
curl -sO [suspicious link removed]
sudo bash wazuh-install.sh -a
```

### Technical Blocker: Port Binding Conflicts with Public Web Server
* **Problem**: The Wazuh Dashboard defaults to HTTPS Port 443, conflicting with public NGINX web server configurations.
* **Resolution**: Modified the Wazuh Dashboard configuration (`/etc/wazuh-dashboard/opensearch_dashboards.yml`) to bind strictly to custom **Port 4443**:

```yaml
# /etc/wazuh-dashboard/opensearch_dashboards.yml
server.port: 4443
server.host: "0.0.0.0"
```

Restart the dashboard and allow port access:

```bash
# Restart Wazuh Dashboard
sudo systemctl restart wazuh-dashboard

# Permit Port 4443 in host firewall
sudo iptables -I INPUT 1 -p tcp -m state --state NEW -m tcp --dport 4443 -j ACCEPT
sudo netfilter-persistent save
``` -->

## 7. Sensor Deployment Verification Summary

At the completion of Part 2, all security sensors are operational and writing structured logs to their designated target paths:

| Component | Target Output Path | Verification Command |
| :--- | :--- | :--- |
| **Suricata 7** | `/var/log/suricata/eve.json` | `sudo tail -n 5 /var/log/suricata/eve.json` |
| **Coraza WAF** | Docker `stderr` (`coraza-waf`) | `docker logs --tail 10 coraza-waf` |
| **Cowrie** | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` | `sudo tail -n 5 /home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| **Fail2ban** | Host `SYSLOG` / `journald` | `sudo journalctl -u fail2ban -n 20` |
| **Wazuh SIEM** | `/var/ossec/logs/alerts/alerts.json` | `sudo tail -n 5 /var/ossec/logs/alerts/alerts.json` |

# Part 3: Telemetry Aggregation Engine, SQLite State Persistence, Web Dashboard & Operational Post-Mortems

This section details the autonomous out-of-band telemetry compiler (`update_metrics.py`), the embedded SQLite database schema, the NGINX web tier, the TanStack/React SOC dashboard integration, and a comprehensive post-mortem repository covering diagnostic commands, performance fixes, and database maintenance.


## 1. Telemetry Processing Engine Architecture (`update_metrics.py`)

ThreatScope decouples data compilation from web serving. Instead of exposing a live database API to the public web tier, a background Python script (`update_metrics.py`) runs periodically via a `cron` wrapper. It ingests raw logs from Suricata, Coraza WAF, and Cowrie, applies stateful deduplication and GeoIP enrichment, and publishes an atomic static JSON payload to `/var/www/threat-data/metrics.json`.

```text
[ Suricata (eve.json) ] ──────┐
[ Cowrie (cowrie.json) ] ─────┼──► [ update_metrics.py ] ──► [ SQLite (state.sqlite3) ]
[ Coraza (Docker logs) ] ─────┘           │
                                          ▼ (Atomic POSIX Swap: tempfile -> os.replace)
                             /var/www/threat-data/metrics.json
                                          │
                                          ▼ (Cache-Control: no-store, no-cache)
                             [ NGINX ] ──► [ React 19 / TanStack Dashboard ]
```

### Key Functional Subsystems

#### A. MaxMind GeoLite2 Geolocation Engine
The engine uses a local MaxMind GeoLite2-City database (`.mmdb`) to translate IP addresses into ISO country codes, country names, and geographic coordinates without external network API calls:

```python
def resolve_geo(ip):
    reader = get_geo_reader()
    if not reader:
        return None
    try:
        resp = reader.city(ip)
        country = resp.country.name or ""
        code = resp.country.iso_code or ""
        lat = resp.location.latitude
        lon = resp.location.longitude
        if country:
            return (country, code, lat, lon)
    except Exception:
        pass
    return None
```

#### B. CIDR-Based Benign Scanner Triage
To prevent research crawlers, internet measurement groups, and benign bots from cluttering the threat feed or blocklists, source IPs are validated against CIDR network definitions using Python's `ipaddress` library:

```python
BENIGN_SUBNETS = [
    # Palo Alto Networks Cortex Xpanse
    "147.185.132.0/23", "198.235.24.0/24", "205.210.31.0/24",
    # The Shadowserver Foundation
    "64.62.197.0/24", "65.49.1.0/24",
    # Censys
    "66.132.172.0/24", "162.142.125.0/24", "167.94.138.0/24",
    # Infrawatch Limited
    "109.160.32.0/24",
    # ONYPHE
    "185.180.143.0/24", "212.83.187.0/24",
]

_BENIGN_NETWORKS = [ipaddress.ip_network(net) for net in BENIGN_SUBNETS]

def is_benign_ip(ip_str):
    """Check if an IP belongs to a known benign scanner subnet."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
        return any(ip in net for net in _BENIGN_NETWORKS)
    except ValueError:
        return False
```

#### C. SHA-256 Deduplication & Event Ingestion
Raw log events are hashed with SHA-256. Primary key constraints in SQLite enforce event uniqueness:

```python
def ingest(db, source, raw, occurrence=1, docker_timestamp=None):
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8", errors="replace").strip()

    event = parse_event(source, text, docker_timestamp)
    if event is None:
        return False

    inserted = db.execute(
        "INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)",
        (source, digest, occurrence, event["at"], event["attack"]),
    )

    if not inserted.rowcount:
        return False

    # Increment KPIs and store unique IPs if genuine global attack
    if event["ip"] and event["attack"] and not event["benign_scanner"] and not is_benign_ip(event["ip"]):
        db.execute(
            """
            INSERT INTO ips(ip, last_seen) VALUES(?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen = CASE
                    WHEN ips.last_seen IS NULL OR excluded.last_seen > ips.last_seen
                    THEN excluded.last_seen
                    ELSE ips.last_seen
                END
            """,
            (event["ip"], event["at"]),
        )
    return True
```

#### D. Atomic POSIX File Operations
To prevent NGINX from serving a partially written file during high-volume log writes, `atomic_write` writes the payload to a temporary file in the same directory before executing an atomic `os.replace` operation:

```python
def atomic_write(target_path, write_fn):
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", dir=target.parent, delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        write_fn(temp_file)

    os.chmod(temp_path, 0o644)
    temp_path.replace(target)  # Atomic POSIX rename
```

---

## 2. Embedded SQLite State Database Schema (`state.sqlite3`)

The collector persists internal state across reboots and log rotations using an embedded SQLite database (`/var/lib/threat-metrics/state.sqlite3`) configured in Write-Ahead Logging (WAL) mode.

```python
def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=60)
    db.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS metadata(
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS cursors(
            key TEXT PRIMARY KEY,
            offset INTEGER,
            prefix TEXT
        );

        CREATE TABLE IF NOT EXISTS occurrences(
            filekey TEXT,
            hash TEXT,
            count INTEGER,
            PRIMARY KEY(filekey, hash)
        );

        CREATE TABLE IF NOT EXISTS events(
            source TEXT,
            hash TEXT,
            occurrence INTEGER,
            at REAL,
            attack INTEGER,
            PRIMARY KEY(source, hash, occurrence)
        );

        CREATE INDEX IF NOT EXISTS event_time ON events(at);

        CREATE TABLE IF NOT EXISTS ips(
            ip TEXT PRIMARY KEY,
            last_seen REAL
        );

        CREATE TABLE IF NOT EXISTS counts(
            kind TEXT,
            name TEXT,
            value INTEGER,
            PRIMARY KEY(kind, name)
        );

        CREATE TABLE IF NOT EXISTS feed(
            id INTEGER PRIMARY KEY,
            at REAL,
            payload TEXT
        );
        """
    )
    return db
```


## 3. Web Tier & Live SOC Dashboard Integration

### NGINX Reverse Proxy Configuration
NGINX serves the generated JSON payload directly from disk using low-overhead alias routes and cache-busting headers:

```nginx
# /etc/nginx/sites-available/threatscope
server {
    listen 80;
    listen [::]:80;
    server_name [suspicious link removed];

    root /var/www/html;
    index index.html;

    # Live static JSON metrics endpoint
    location = /api/metrics.json {
        alias /var/www/threat-data/metrics.json;
        default_type application/json;
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        add_header Access-Control-Allow-Origin "*" always;
    }

    # Plaintext threat IP blocklist export
    location = /api/ips.txt {
        alias /var/www/threat-data/ips.txt;
        default_type text/plain;
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
    }

    # Single Page Application Frontend Routing
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

Enable the configuration and reload NGINX:
```bash
sudo ln -s /etc/nginx/sites-available/threatscope /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Frontend Architecture
* **Stack**: **TanStack Start v1, React 19, Bun runtime, Tailwind CSS v4**.
* **State Polling**: Uses TanStack Query to fetch `/api/metrics.json` every 60 seconds with fallback mock data for offline testing:

```tsx
import { useQuery } from '@tanstack/react-query';

export function useThreatMetrics() {
  return useQuery({
    queryKey: ['threat-metrics'],
    queryFn: async () => {
      const res = await fetch('/api/metrics.json', { cache: 'no-store' });
      if (!res.ok) throw new Error('Failed to load metrics');
      return res.json();
    },
    refetchInterval: 60000, // 60-second polling
    staleTime: 30000,
  });
}
```

* **UI Features**:
  * *Sticky Attack Ticker*: Displays a streaming log of recent attacks.
  * *Parallax Hero*: Sensor health indicators (`SURICATA`, `CORAZA`, `COWRIE`).
  * *3D Interactive Threat Globe*: Rendered with WebGL using Cobe, showing live attack arcs from GeoIP coordinates.
  * *Analytical Charts*: Recharts visualizations showing attack vectors, targeted ports, and password frequency word clouds.


## 4. Cron Execution & Concurrency Locking (`flock`)

To prevent overlapping script runs from locking the SQLite database (`sqlite3.OperationalError: database is locked`), schedule execution via `cron` using a non-blocking Linux kernel lock (`flock`):

```bash
# Create automated cron task in /etc/cron.d/threat-metrics
sudo bash -c 'cat << "EOF" > /etc/cron.d/threat-metrics
* * * * * root /usr/bin/flock -n /run/threat-metrics.lock /usr/bin/python3 /opt/threat-dashboard/update_metrics.py >> /var/log/threat-metrics.log 2>&1
EOF'

sudo chmod 0644 /etc/cron.d/threat-metrics
```

## 5. Operational Post-Mortems & Command Reference

### Incident 1: Inode vs. `mtime` Cursor Invalidation (213s CPU Spike)
* **Symptom**: Execution time spiked from <1s to 213.6 seconds per run, consuming 100% CPU (378 million function calls).
* **Diagnostic Steps**:
  ```bash
  # Profile Python script execution time
  sudo python3 -m cProfile -s tottime /opt/threat-dashboard/update_metrics.py --skip-docker | head -n 25
  ```
* **Root Cause**: The file cursor key was calculated using file modification time: `f"{path}:{stat.st_mtime_ns}:{stat.st_size}"`. Because `mtime` changes on every log write, the lookup query `SELECT offset FROM cursors` always failed, forcing the script to re-parse all 890 MB of log data from byte 0 on every execution (...oops).
* **Resolution**: Switched the file cursor key to use persistent Linux device (`st_dev`) and inode (`st_ino`) numbers, and added truncation checks:
  ```python
  # Updated persistent file key logic
  file_key = f"{path}:{stat.st_dev}:{stat.st_ino}"

  # Handle log rotation or file truncation gracefully
  if offset > stat.st_size:
      offset = 0
  ```
  *Result*: Execution time dropped from 213.6 seconds to 1.5 seconds.

---

### Incident 2: The 21 GB SQLite Disk Explosion & Database Surgery
* **Symptom**: Root partition hit 100% utilization, causing `sqlite3.OperationalError: disk I/O error`.
* **Diagnostic Commands**:
  ```bash
  # Identify root partition utilization
  df -h
  
  # Find largest database files on system
  sudo find / -xdev -type f -size +100M -exec ls -lh {} +
  ```
* **Root Cause**: Re-reading log files repeatedly inserted millions of duplicate rows into `events` and `occurrences`, inflating B-tree indexes to 21 GB. Standard `VACUUM` failed due to lack of temporary disk space. Mind you this is a free cloud instance with 50 GB for free (about 44 available).
* **Database Extraction & Surgery Procedure**:
  ```bash
  # Step 1: Dump schema and extract essential state tables
  sudo sqlite3 /var/lib/threat-metrics/state.sqlite3 ".schema" > /tmp/schema.sql
  sudo sqlite3 /var/lib/threat-metrics/state.sqlite3 ".dump metadata counts ips cursors feed" > /tmp/essential_data.sql

  # Step 2: Build fresh compacted database
  sudo sqlite3 /tmp/clean_state.sqlite3 < /tmp/schema.sql
  sudo sqlite3 /tmp/clean_state.sqlite3 < /tmp/essential_data.sql

  # Step 3: Verify integrity of fresh database
  sudo sqlite3 /tmp/clean_state.sqlite3 "PRAGMA integrity_check;"

  # Step 4: Atomically replace bloated database with clean 5 MB database
  sudo rm -f /var/lib/threat-metrics/state.sqlite3-wal /var/lib/threat-metrics/state.sqlite3-shm /var/lib/threat-metrics/state.sqlite3
  sudo mv /tmp/clean_state.sqlite3 /var/lib/threat-metrics/state.sqlite3
  ```
  *Result*: Reclaimed 21 GB of disk space and reduced database size to 5 MB while retaining all historical threat counts and IP blocklists.

---

### Incident 3: Telemetry Sanitization & Private IP Filtering
* **Symptom**: Private local network addresses (e.g., `10.0.0.115`) appeared on the public dashboard as `unknown (XX)`.
* **Resolution**: Added RFC 1918 private network filtering to the parsing logic and purged non-public records from SQLite:
  ```python
  def valid_ip(value):
      try:
          ip = ipaddress.ip_address(str(value).strip())
          val_str = str(value).strip()
          if not ip.is_global or val_str in IGNORED_IPS or is_benign_ip(val_str):
              return None
          return ip.compressed
      except ValueError:
          return None
  ```
  ```bash
  # Purge internal/invalid records from the live feed database
  sudo sqlite3 /var/lib/threat-metrics/state.sqlite3 "DELETE FROM feed WHERE country_code = 'XX' OR src_ip LIKE '10.%';"
  ```

---

### 4. System Emergency Maintenance Command Quick-Reference

| Administrative Action | Exact Shell Command | Purpose |
| :--- | :--- | :--- |
| **Inspect Active Lock PID** | `sudo fuser -v /var/lib/threat-metrics/state.sqlite3` | Identifies processes holding open SQLite database write locks. |
| **Kill Stuck Collector Runs** | `sudo pkill -9 -f update_metrics.py` | Forcefully terminates hung collector processes. |
| **Clear Stale Kernel Locks** | `sudo rm -f /run/threat-metrics.lock` | Clears stale lockfiles to unblock scheduled cron executions. |
| **Truncate Docker Logs** | `sudo truncate -s 0 /var/lib/docker/containers/*/*-json.log` | Instantly frees disk space from unrotated container logs. |
| **Prune Unused Docker Artifacts**| `docker system prune -a -f --volumes` | Reclaims space from inactive container images and build layers. |
| **Test Manual Script Run** | `sudo flock -n /run/threat-metrics.lock /usr/bin/python3 /opt/threat-dashboard/update_metrics.py` | Executes the collector manually with kernel lock protection. |
| **Inspect JSON Output** | `jq . /var/www/threat-data/metrics.json \| head -n 30` | Validates generated static metrics payload syntax and contents. |

# Part 4: System Maintenance, Automated Pruning, Active Threat Enforcement & Health Monitoring

This final section completes the ThreatScope educational guide by focusing on long-term system administration, disk storage hygiene, active kernel firewall enforcement via `ipset`, AbuseIPDB threat intelligence sharing, and automated health checks.



## 1. Automated Log Rotation & Storage Hygiene

High-volume security sensors generate millions of raw event logs daily. Without strict log rotation rules, log files will exhaust disk storage and lead to system failures.

### A. Configuring Linux `logrotate` for Security Logs
Create custom rotation configurations for Suricata and Cowrie under `/etc/logrotate.d/`:

```bash
# Suricata EVE JSON Log Rotation Configuration
sudo bash -c 'cat << "EOF" > /etc/logrotate.d/suricata
/var/log/suricata/eve.json {
    daily
    rotate 7
    missingok
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        /usr/bin/suricatasc -c reload-rules
    endscript
}
EOF'

# Cowrie Honeypot Log Rotation Configuration
sudo bash -c 'cat << "EOF" > /etc/logrotate.d/cowrie
/home/cowrie/cowrie/var/log/cowrie/cowrie.json {
    daily
    rotate 7
    missingok
    compress
    delaycompress
    notifempty
}
EOF'

# Test logrotate configuration syntax
sudo logrotate -d /etc/logrotate.d/suricata
```

### B. Truncating Unrotated Container Logs
Docker container logs (`/var/lib/docker/containers/`) do not rotate automatically unless explicitly configured in `/etc/docker/daemon.json`. To instantly reclaim disk space without stopping running containers:

```bash
# Truncate all container JSON logs to 0 bytes in-place
sudo truncate -s 0 /var/lib/docker/containers/*/*-json.log
```

---

## 2. Docker Container Pruning & Storage Reclamation

Over time, unused Docker images, dangling build caches, and anonymous volumes consume gigabytes of storage on the root partition.

```bash
# Forcefully remove unused containers, networks, images, and anonymous volumes
docker system prune -a -f --volumes

# Verify reclaimed disk capacity
df -h /
```

---

## 3. Active Kernel Threat Enforcement via `ipset` & `iptables`

While ThreatScope acts as a passive monitoring and visualization platform, `update_metrics.py` generates a clean list of verified malicious IPs in `/var/www/threat-data/ips.txt` (excluding RFC 1918 subnets and benign research crawlers). This list can feed directly into an `ipset` kernel data structure for sub-millisecond packet dropping.

### Step 1: Create the Kernel IP Set
```bash
# Create an in-kernel hash set capable of holding up to 65,536 IP addresses
sudo ipset create hostile_ips hash:ip maxelem 65536 hashsize 16384
```

### Step 2: Attach `iptables` Rule
Insert a top-priority `iptables` rule that drops any incoming packet matching the `hostile_ips` set:

```bash
# Insert rule at position 1 in the INPUT chain
sudo iptables -I INPUT 1 -m set --match-set hostile_ips src -j DROP

# Save the iptables rule persistently
sudo netfilter-persistent save
```

### Step 3: Populate the IP Set from `ips.txt`
Build a shell script (`/opt/threat-dashboard/update_ip_blocklist.sh`) to synchronize the live `ips.txt` export into the `hostile_ips` kernel set:

```bash
#!/usr/bin/env bash
set -euo pipefail

BLOCKLIST="/var/www/threat-data/ips.txt"

if [ -f "$BLOCKLIST" ]; then
    # Flush temporary working set
    sudo ipset create hostile_ips_tmp hash:ip maxelem 65536 hashsize 16384 2>/dev/null || sudo ipset flush hostile_ips_tmp
    
    # Read verified malicious IPs line-by-line and populate temporary set
    while IFS= read -r ip; do
        if [[ -n "$ip" ]]; then
            sudo ipset add hostile_ips_tmp "$ip" -exist
        fi
    done < "$BLOCKLIST"
    
    # Swap temporary set into active production set atomically
    sudo ipset swap hostile_ips_tmp hostile_ips
    sudo ipset destroy hostile_ips_tmp
fi
```

Make the script executable and schedule it via `cron`:
```bash
sudo chmod +x /opt/threat-dashboard/update_ip_blocklist.sh
```

---

## 4. AbuseIPDB Threat Intelligence Staging & Reporting

Sharing verified threat telemetry with global security platforms like AbuseIPDB strengthens collective defense.

### Bulk Export Criteria
To maintain high reporting accuracy and avoid false positives:
1. Filter out known research crawlers (Censys, Shadowserver, Palo Alto Cortex Xpanse) using the `is_benign_ip()` module.
2. Only export IPs tagged with explicit attack categories (SSH brute-force, WAF rule violations, or NIDS exploit signatures).
3. Validate that each target IP was observed active within the last 30 days.

### AbuseIPDB CSV Export Format
Extract formatted threat metrics directly from SQLite for bulk API submission:

```bash
sudo sqlite3 /var/lib/threat-metrics/state.sqlite3 -csv -header \
"SELECT ip, strftime('%Y-%m-%dT%H:%M:%SZ', datetime(last_seen, 'unixepoch')) AS Categories 
 FROM ips 
 WHERE last_seen >= strftime('%s', 'now', '-30 days')
 ORDER BY last_seen DESC;" > /var/www/threat-data/abuseipdb_export.csv
```

---

## 5. Automated System Health Verification Commands

To verify that the platform remains healthy and fully operational, run these diagnostic sanity checks:

```bash
# 1. Verify that update_metrics.py executes under 2 seconds
time sudo /usr/bin/flock -n /run/threat-metrics.lock /usr/bin/python3 /opt/threat-dashboard/update_metrics.py

# 2. Confirm the size of the SQLite state database remains under 50 MB
ls -lh /var/lib/threat-metrics/state.sqlite3

# 3. Check for stale lockfiles or stuck processes
ps aux | grep update_metrics.py

# 4. Verify NGINX is serving live HTTP 200 responses for API endpoints
curl -I [suspicious link removed]
curl -I [suspicious link removed]

# 5. Check log freshness for Suricata and Cowrie
echo "Suricata Log Age (seconds): $(( $(date +%s) - $(stat -c %Y /var/log/suricata/eve.json) ))"
echo "Cowrie Log Age (seconds): $(( $(date +%s) - $(stat -c %Y /home/cowrie/cowrie/var/log/cowrie/cowrie.json) ))"
```

# Part 5: Future Roadmap & Conceptual Explorations

This section outlines planned architectural extensions for **ThreatScope**, focusing on AI-assisted vulnerability intelligence, real-time out-of-band mobile alerts for perimeter threats, automated system watchdogs, and autonomous SOC threat triage.


## 1. AI-Powered Cybersecurity News & Vulnerability Explainer

To complement real-time attack telemetry, **ThreatScope** may feature an integrated cybersecurity news and threat intelligence module designed to translate complex vulnerability disclosures into accessible, educational insights.

* **Automated News Ingestion**: Ingests structured security advisories and zero-day announcements from sources such as the **CISA Known Exploited Vulnerabilities (KEV)** catalog and **NIST National Vulnerability Database (NVD)**.
* **AI Summarization Pipeline**: An out-of-band Python background process passes raw advisory text to a Large Language Model (such as the **Gemini API**) to generate a structured, 3-part educational card for each vulnerability:
  1. **Executive Summary**: A concise, non-technical overview of the security event.
  2. **Exploit Mechanics ("How It Works")**: A beginner-friendly breakdown of the underlying flaw (e.g., SQL injection, buffer overflow, broken authentication) without overwhelming technical jargon.
  3. **Impact & Severity ("Why It Matters")**: Practical context detailing real-world exposure risks and recommended patching steps.
  
  This can be used to explain to non-technical stakeholders the potential impact of a security breach that is now possible because of the discussed exploit.
* **Decoupled Payload Publishing**: As with all ThreatScope telemetry, the AI pipeline compiles these insights into a static JSON payload served directly by NGINX to a dedicated card on the React dashboard.



## 2. Real-Time Perimeter & Infrastructure Mobile Alerting

While standard internet brute-force traffic on Port 22 is silently redirected to the **Cowrie Honeypot**, any connection attempt targeting my custom port represents an active probe against the actual host management interface. To ensure immediate awareness without requiring manual log checking, a real-time mobile alerting engine (via services like Pushover, Telegram Webhooks, or Twilio) will be integrated.

* **Management SSH Ban Alerts**: Triggers an instant mobile push notification whenever **Fail2ban** executes a ban on my custom port. This provides immediate notification that an attacker has discovered and probed my actual management interface rather than the honeypot decoy.
* **Storage & Memory Capacity Watchdog**: Automatically monitors root filesystem space and triggers an alert if storage usage exceeds safe thresholds (e.g., 85%), preventing SQLite database locking and I/O failures before they cause an outage.
* **Sensor Stack Heartbeat Monitor**: Continuously tracks event log freshness for Suricata, Coraza WAF, and Cowrie. If any sensor daemon crashes or stops outputting logs for more than 5 minutes, a high-priority alert is dispatched to my phone.



## 3. Autonomous Threat Triage & Intelligence Escalation

To eliminate manual log review and accelerate incident response, ThreatScope will incorporate an automated multi-tier triage hierarchy:

* **Automated Traffic Classification**:
  * **Tier 0 (Benign Research Crawlers)**: Automatically filters out legitimate scanners (e.g., Shadowserver, Censys, Palo Alto Cortex Xpanse) based on CIDR subnets and known identity signatures.
  * **Tier 1 (Anonymized Proxies)**: Cross-references incoming IPs against live Tor exit node and commercial VPN lists, automatically tagging dashboard feed items with `Tor` or `Proxy` indicators.
  * **Tier 2 (Active Hostile Threat Actors)**: Flags IPs engaging in aggressive WAF exploit attempts, malicious payload downloads, or honeypot command execution.


## 4. Target Project Architecture Roadmap

When fully realized, the ThreatScope repository will be organized into modular subsystems:

* **`collector/`**: The core Python telemetry processing engine, SQLite schema definitions, MaxMind GeoIP integration, and `flock` execution wrappers.
* **`sensors/`**: Configuration profiles for Suricata NIDS, containerized Coraza WAF (Caddy + OWASP CRS 4.x), Cowrie Honeypot, and Fail2ban host defense.
* **`scripts/`**: Automation tools for kernel `ipset` synchronization, root partition storage watchdogs, and AbuseIPDB intelligence reporting.
* **`frontend/`**: The TanStack Start / React 19 SOC Dashboard featuring the interactive 3D WebGL globe, real-time attack ticker, and analytical charts.
* **`docs/`**: The complete 5-part educational guide and architectural post-mortems for GitHub.
