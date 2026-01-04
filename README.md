# CrackBox 🔐

> A hardened, interactive credential attack toolkit for authorized penetration testing engagements.

---

## What is CrackBox?

CrackBox is an interactive command-line toolkit that wraps industry-standard offensive security tools — `hashcat`, `john`, `hydra`, and `netexec` — into a guided, menu-driven workflow. Instead of memorizing flags and syntax across four different tools, you answer plain-English prompts and CrackBox builds and executes the right command for you.

It was built out of a real frustration felt on engagements: switching between tools mid-assessment breaks flow, and copy-pasting commands from notes introduces errors. CrackBox keeps everything in one place.

---

## Features

| Module | What it does |
|--------|-------------|
| **Hash cracking** | Identifies hash type via `hash-identifier`, then cracks with `hashcat` or `john` |
| **Password spraying** | Sprays credentials over SMB, WinRM, SSH, MSSQL, RDP, FTP via `netexec`; supports NTLM pass-the-hash |
| **Targeted brute-force** | Pitchfork-mode `hydra` attack with built-in lockout policy awareness |
| **JWT cracking** | Cracks HS256/384/512 secrets with `hashcat`; detects and strips `none`-algorithm tokens |

### Security-first design
- No `shell=True` — no command injection, no argument smuggling
- Credentials never appear in log files (redacted with `***`)
- Sensitive material (hashes, tokens) written to temp files, never passed as CLI arguments
- Temp files always cleaned up, even on crash or `Ctrl+C`
- Microsecond-timestamped output files prevent accidental overwrites

---

## Requirements

- Linux (tested on Kali 2024.x and Parrot OS 6.x)
- Python 3.8+
- The following tools in `$PATH`:

| Tool | Install |
|------|---------|
| `hashcat` | `sudo apt install hashcat` |
| `john` | `sudo apt install john` |
| `hydra` | `sudo apt install hydra` |
| `netexec` | `pip install netexec` |
| `hash-identifier` | `sudo apt install hash-identifier` |

---

## Installation

```bash
git clone https://github.com/verygoodsecbadsec/crackbox.git
cd crackbox
chmod +x install.sh
./install.sh
```

---

## Quick Start

```bash
python3 crackbox.py
```

You will be presented with an interactive menu:

```
   ____                _   ____
  / ___|_ __ __ _  ___| |_| __ )  _____  __
 | |   | '__/ _` |/ __| __|  _ \ / _ \ \/ /
 | |___| | | (_| | (__| |_| |_) | (_) >  <
  \____|_|  \__,_|\___|\__|____/ \___/_/\_\
         Hardened Credential Attack Toolkit

What would you like to do?
  1) Crack a hash
  2) Password spraying
  3) Targeted brute-forcing (pitchfork)
  4) JWT signature cracking
  5) Exit
```

See [docs/commonusage.md](docs/commonusage.md) for real-world usage examples.

---

## Output Files

| File | Contents |
|------|----------|
| `crackbox_YYYYMMDD_HHMMSS.log` | Full session log (credentials redacted) |
| `cracked_HHMMSS_ffffff.txt` | Hashcat cracked hashes |
| `jwt_cracked_HHMMSS_ffffff.txt` | Cracked JWT secrets |

---

## Project Structure

```
crackbox/
├── crackbox.py          # Main toolkit
├── install.sh           # Dependency checker and installer
├── .gitignore
├── LICENSE
├── README.md
└── docs/
    └── common-usage.md  # Annotated usage examples
```
---

## Legal Notice

This tool is intended for authorized use in CTF competitions, security research, and controlled test environments only. Capturing traffic on networks you do not own or have explicit permission to monitor is illegal in most jurisdictions. The author accepts no liability for unauthorized use.

---

## License
 - This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
