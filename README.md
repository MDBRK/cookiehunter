# CookieHunter

**CookieHunter** is a fast Python script that:

- Extracts and analyzes cookies from a target URL
- Decodes Base64, JWT, JSON, and detects hashes
- Suggests manual actions (e.g. flipping booleans, session testing)
- Optionally brute-forces common paths using `curl` and cookies

---

## Features

- Cookie analysis with URL, Base64, JSON, JWT decoding
- Detects possible session/auth tokens or flags
- Optional brute-force of paths using a wordlist + curl + cookies
- Easy to extend and fast to use

---

## Requirements

Install dependencies using the provided script:

```bash
python3 install_requirements.py

---
## script usage 

```bash
python3 cookiehunter.py <target_url>

