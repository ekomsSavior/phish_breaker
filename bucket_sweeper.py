import subprocess
import datetime
import os
import re
import requests
import argparse

DEFAULT_FILENAMES = [
    "index.html",
    "login.html",
    "verify.html",
    "signup.html",
    "reset.html"
]

def check_file_exists(url):
    try:
        result = subprocess.check_output(['curl', '-I', url], stderr=subprocess.DEVNULL, text=True)
        if "200" in result:
            content_type = re.search(r'Content-Type:\s*(.+)', result, re.IGNORECASE)
            content_length = re.search(r'Content-Length:\s*(\d+)', result, re.IGNORECASE)
            ctype = content_type.group(1).strip() if content_type else 'unknown'
            clen = content_length.group(1).strip() if content_length else 'unknown'
            print(f"[+] Found: {url} (Type: {ctype}, Length: {clen})")
            return True, ctype, clen
        else:
            return False, None, None
    except Exception as e:
        print(f"[!] Error checking {url}: {e}")
        return False, None, None

def fetch_file_body(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            return ""
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return ""

def extract_hidden_domains(html):
    try:
        urls = re.findall(r'https?://[^\s\'"<>]+', html)
        js_redirects = re.findall(r'window\.location(?:\.href|\.replace)?\s*=\s*[\'"]([^\'"]+)', html)
        all_links = sorted(set(urls + js_redirects))
        if all_links:
            print(f"    [+] Hidden domains/links found:")
            for d in all_links:
                print(f"      - {d}")
        return all_links
    except Exception as e:
        print(f"[!] Error extracting hidden domains: {e}")
        return []

def save_report(bucket_url, found_files):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_name = f"{report_dir}/report_bucket_sweeper_{timestamp}.txt"
    with open(report_name, "w") as f:
        f.write(f"Bucket base URL: {bucket_url}\n\n")
        if found_files:
            for file, info in found_files.items():
                ctype, clen, hidden_domains = info
                f.write(f"Found file: {file}\n")
                f.write(f"  Content-Type: {ctype}\n")
                f.write(f"  Content-Length: {clen}\n")
                if hidden_domains:
                    f.write("  Hidden domains/links:\n")
                    for domain in hidden_domains:
                        f.write(f"    - {domain}\n")
                f.write("\n")
        else:
            f.write("No accessible files found.\n")
    print(f"[+] Saved report as {report_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Google bucket sweeper")
    parser.add_argument('--wordlist', help='Path to custom filename wordlist (one per line)')
    args = parser.parse_args()

    bucket_url = input("Enter Google bucket base URL (with trailing slash or full file URL): ").strip()

    # Load custom wordlist if provided
    filenames = DEFAULT_FILENAMES
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as wl:
                filenames = [line.strip() for line in wl if line.strip()]
        except Exception as e:
            print(f"[!] Failed to load wordlist: {e}")
            exit(1)

    found_files = {}

    # Always check base URL
    exists, ctype, clen = check_file_exists(bucket_url)
    if exists:
        html = fetch_file_body(bucket_url)
        hidden_domains = extract_hidden_domains(html)
        found_files[bucket_url] = (ctype, clen, hidden_domains)

    # If ends with /, append filenames
    if bucket_url.endswith("/"):
        for filename in filenames:
            file_url = bucket_url + filename
            exists, ctype, clen = check_file_exists(file_url)
            if exists:
                html = fetch_file_body(file_url)
                hidden_domains = extract_hidden_domains(html)
                found_files[file_url] = (ctype, clen, hidden_domains)

    save_report(bucket_url, found_files)
