import requests
import sys
import base64
import json
import re
import subprocess
import threading
from urllib.parse import unquote
from jwt import decode as jwt_decode, get_unverified_header, InvalidTokenError

COMMON_WORDLIST = "common.txt"
brute_force_required = False
cookie_dict = {}
brute_force_thread = None

def print_header():
    print("="*75)
    print("COOKIE ANALYZER + CURL PATH BRUTE FORCER        AUTHOR : Mohamed Briki")
    print("="*75)

def decode_base64(data):
    try:
        padding = 4 - len(data) % 4
        if padding and padding < 4:
            data += "=" * padding
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return None

def detect_hash(s):
    hash_types = {
        32: 'MD5',
        40: 'SHA-1',
        64: 'SHA-256',
        128: 'SHA-512'
    }
    if re.fullmatch(r"[a-fA-F0-9]+", s):
        return hash_types.get(len(s), None)
    return None

def try_jwt_decode(token):
    try:
        header = get_unverified_header(token)
        payload = jwt_decode(token, options={"verify_signature": False})
        return {"header": header, "payload": payload}
    except InvalidTokenError:
        return None

def should_bruteforce(value):
    keywords = ['admin', 'token', 'auth', 'session']
    return any(k in value.lower() for k in keywords)

def brute_force_paths(url, cookies):
    print("\nStarting brute-force on common paths using curl...\n")
    try:
        with open(COMMON_WORDLIST, 'r') as wordlist:
            for line in wordlist:
                path = line.strip()
                full_url = f"{url.rstrip('/')}/{path}"
                cookie_string = "; ".join(f"{k}={v}" for k, v in cookies.items())
                try:
                    result = subprocess.run(
                        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-b", cookie_string, full_url],
                        capture_output=True, text=True, timeout=5
                    )
                    status_code = result.stdout.strip()
                    if status_code.startswith("2") or status_code.startswith("3"):
                        print(f"  [{status_code}] {full_url}")
                except subprocess.TimeoutExpired:
                    continue
    except FileNotFoundError:
        print(f"Wordlist file '{COMMON_WORDLIST}' not found. Skipping brute-force.")

def analyze_cookie(name, value):
    global brute_force_required
    print(f"\nCookie Name: {name}")
    print(f"  Raw Value: {value}")

    decoded_url = unquote(value)
    print(f"  URL Decoded: {decoded_url}")

    b64_decoded = decode_base64(decoded_url)
    if b64_decoded:
        print(f"  Base64 Decoded: {b64_decoded}")
    else:
        print("  Base64 Decoded: Not Base64 or failed")

    try:
        json_data = json.loads(b64_decoded if b64_decoded else decoded_url)
        print("  JSON Parsed:")
        print(json.dumps(json_data, indent=4))
    except:
        print("  JSON Parsed: Not JSON")

    if value.count('.') == 2:
        jwt_result = try_jwt_decode(value)
        if jwt_result:
            print("  JWT Detected:")
            print("  Header:", jwt_result['header'])
            print("  Payload:")
            print(json.dumps(jwt_result['payload'], indent=4))
        else:
            print("  JWT Parse: Failed")

    hash_type = detect_hash(value)
    if hash_type:
        print(f"  Possible Hash Detected: {hash_type}")

    print("\n  Possible Actions:")
    lower_val = value.lower()
    if 'admin' in lower_val or 'true' in lower_val or 'false' in lower_val:
        print("    - Flip boolean values (e.g., admin=false → true).")
        brute_force_required = True
    if b64_decoded and 'admin' in b64_decoded.lower():
        print("    - Base64 decoded contains 'admin'. Try flipping and re-encoding.")
        brute_force_required = True
    if name.lower() in ['session', 'sessionid', 'auth', 'token']:
        print("    - May be session/auth token. Try session fixation or brute force.")
        brute_force_required = True
    if 'flag' in lower_val or 'flag' in decoded_url.lower():
        print("    - Might directly contain a flag.")
    if hash_type:
        print(f"    - Brute force this {hash_type} hash if used as password/session.")
    if value.count('.') == 2:
        print("    - Looks like JWT. Try keyless attack or brute force with known wordlists.")
        brute_force_required = True
    print("    - Use this cookie with curl to test restricted paths (e.g., /admin, /flag).")

def extract_analyze_then_bruteforce(target_url):
    global brute_force_thread
    try:
        session = requests.Session()
        response = session.get(target_url, timeout=10)
        cookies = session.cookies

        if not cookies:
            print("\nNo cookies found at this URL.")
            return

        print(f"\nCookies Found for {target_url}:\n")
        for cookie in cookies:
            name = cookie.name
            value = cookie.value
            cookie_dict[name] = value
            analyze_cookie(name, value)
            print()  # Add space between cookies

        if brute_force_required:
            answer = input("\n[?] Bruteforce conditions met. Do you want to start curl brute-force? (y/n): ").lower()
            if answer == 'y':
                brute_force_thread = threading.Thread(target=brute_force_paths, args=(target_url, cookie_dict))
                brute_force_thread.start()

    except requests.exceptions.RequestException as e:
        print(f"\nFailed to fetch {target_url}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 cookiehunter.py <url>")
        sys.exit(1)

    print_header()
    extract_analyze_then_bruteforce(sys.argv[1])
