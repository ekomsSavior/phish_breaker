import subprocess
import os
import socket
import requests
import time
import sys
import re
import ssl
import base64
from urllib.parse import urlparse, urljoin

try:
    from shodan import Shodan
    SHODAN_ENABLED = True
except ImportError:
    SHODAN_ENABLED = False

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
VT_API_KEY = "YOUR_VT_API_KEY"

def extract_emails(html):
    return re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html)

def extract_inputs(html):
    return re.findall(r"<input[^>]*name=[\"']?([^\"'> ]+)", html, re.IGNORECASE)

def extract_iframes(html):
    return re.findall(r"<iframe[^>]+(?:src|data-src)=['\"]?([^\"'>]+)", html, re.IGNORECASE)

def extract_scripts(html, domain):
    scripts = re.findall(r"<script[^>]+src=['\"]?([^\"'>]+)", html, re.IGNORECASE)
    return [s for s in scripts if domain not in s]

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return s.getpeercert()
    except Exception as e:
        return f"[!] SSL Error: {e}"

def decode_base64_target(text):
    matches = re.findall(r"target=([A-Za-z0-9+/=]+)", text)
    decoded_targets = []
    for encoded in matches:
        try:
            decoded = base64.b64decode(encoded).decode('utf-8')
            decoded_targets.append(decoded)
        except Exception:
            continue
    return decoded_targets

def run_ultra_recon(target):
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    parsed = urlparse(target)
    hostname = parsed.hostname or target.replace("http://", "").replace("https://", "").strip("/")
    safe_name = hostname.replace("/", "_")
    report_path = f"reports/{safe_name}_ultrarecon_{timestamp}.txt"
    os.makedirs("reports", exist_ok=True)

    def log(line):
        print(line)
        with open(report_path, "a") as report:
            report.write(line + "\n")

    log(f"=== ULTRA RECON REPORT ===\nTarget: {target}\nTimestamp: {timestamp}\n")

    # Resolve IP
    try:
        ip = socket.gethostbyname(hostname)
        log(f"[+] Resolved IP: {ip}")
    except socket.gaierror:
        ip = None
        log(f"[-] Could not resolve domain: {hostname}")

    # WHOIS
    log("\n=== WHOIS ===")
    try:
        result = subprocess.check_output(["whois", hostname], stderr=subprocess.DEVNULL).decode()
        log(result)
    except Exception:
        result = ""
        log("[-] WHOIS failed")

    # HTTP Headers
    log("\n=== HTTP Headers ===")
    headers = None
    try:
        headers = requests.get(f"http://{hostname}", timeout=10).headers
    except:
        try:
            headers = requests.get(f"https://{hostname}", timeout=10).headers
        except:
            headers = None

    if headers:
        for k, v in headers.items():
            log(f"{k}: {v}")
    else:
        log("[-] Could not retrieve HTTP headers")

    # robots.txt
    log("\n=== robots.txt ===")
    try:
        resp = requests.get(f"http://{hostname}/robots.txt", timeout=10)
        if resp.status_code == 200:
            log(resp.text)
        else:
            raise Exception()
    except:
        try:
            resp = requests.get(f"https://{hostname}/robots.txt", timeout=10)
            if resp.status_code == 200:
                log(resp.text)
            else:
                log("[-] robots.txt not found")
        except:
            log("[-] Error retrieving robots.txt")

    # Redirect trace
    log("\n=== Redirect Trace ===")
    try:
        resp = requests.get(f"http://{hostname}", timeout=10, allow_redirects=True)
        for r in resp.history:
            log(f"{r.status_code} -> {r.url}")
        log(f"{resp.status_code} -> {resp.url}")
    except:
        try:
            resp = requests.get(f"https://{hostname}", timeout=10, allow_redirects=True)
            for r in resp.history:
                log(f"{r.status_code} -> {r.url}")
            log(f"{resp.status_code} -> {resp.url}")
        except:
            log("[-] Redirect trace failed")

    # Meta refresh + base64 decode
    try:
        html = requests.get(target, timeout=15).text
        decoded_targets = decode_base64_target(html)
        if decoded_targets:
            log("\n=== Decoded base64 targets ===")
            for d in decoded_targets:
                log(f"- {d}")
    except:
        log("\n[-] Failed to fetch HTML for base64/meta refresh check")

    # SSL cert
    log("\n=== SSL Certificate ===")
    ssl_info = get_ssl_info(hostname)
    log(str(ssl_info))

    # Input fields, iframes, scripts, meta tags, emails
    if html:
        log("\n=== Input Fields ===")
        for i in extract_inputs(html) or ["- None"]:
            log(f"- {i}")
        log("\n=== Iframes ===")
        for i in extract_iframes(html) or ["- None"]:
            log(f"- {i}")
        log("\n=== External Scripts ===")
        for i in extract_scripts(html, hostname) or ["- None"]:
            log(f"- {i}")
        log("\n=== Emails ===")
        for i in extract_emails(html) or ["- None"]:
            log(f"- {i}")
        log("\n=== Meta Tags ===")
        for i in re.findall(r"<meta[^>]+>", html, re.IGNORECASE) or ["- None"]:
            log(f"- {i}")

    # VirusTotal domain report
    log("\n=== VirusTotal Domain Report ===")
    if VT_API_KEY:
        try:
            vt = requests.get(f"https://www.virustotal.com/api/v3/domains/{hostname}",
                              headers={"x-apikey": VT_API_KEY}, timeout=15)
            if vt.status_code == 200:
                stats = vt.json()["data"]["attributes"]["last_analysis_stats"]
                for k, v in stats.items():
                    log(f"{k.capitalize()}: {v}")
            else:
                log(f"[-] VT domain lookup failed: {vt.status_code}")
        except Exception as e:
            log(f"[-] VT domain error: {e}")
    else:
        log("[-] VT API key not set")

    # VirusTotal IP report
    if ip and VT_API_KEY:
        log("\n=== VirusTotal IP Report ===")
        try:
            vt = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                              headers={"x-apikey": VT_API_KEY}, timeout=15)
            if vt.status_code == 200:
                stats = vt.json()["data"]["attributes"]["last_analysis_stats"]
                for k, v in stats.items():
                    log(f"{k.capitalize()}: {v}")
            else:
                log(f"[-] VT IP lookup failed: {vt.status_code}")
        except Exception as e:
            log(f"[-] VT IP error: {e}")

    # Shodan
    if ip and SHODAN_ENABLED:
        log("\n=== Shodan ===")
        try:
            api = Shodan(SHODAN_API_KEY)
            data = api.host(ip)
            log(f"IP: {data.get('ip_str', 'N/A')}")
            log(f"Org: {data.get('org', 'N/A')}")
            log(f"ISP: {data.get('isp', 'N/A')}")
            log(f"Hostnames: {', '.join(data.get('hostnames', []))}")
            log(f"Ports: {', '.join(map(str, data.get('ports', [])))}")
        except Exception as e:
            log(f"[-] Shodan error: {e}")
    else:
        log("\n[-] Shodan not enabled or IP missing")

    # Nmap
    if ip:
        log("\n=== Nmap ===")
        try:
            nmap = subprocess.check_output(["nmap", "-sV", "--top-ports", "1000", ip], timeout=240).decode()
            log(nmap)
        except Exception as e:
            log(f"[-] Nmap error: {e}")

    # DIRB
    log("\n=== DIRB ===")
    try:
        dirb = subprocess.check_output(
            ["dirb", target, "/usr/share/dirb/wordlists/common.txt", "-r", "-S"],
            stderr=subprocess.DEVNULL,
            timeout=600
        ).decode()
        log(dirb)
    except Exception as e:
        log(f"[-] DIRB error: {e}")

    # Abuse contacts (from WHOIS) → just before reporting
    log("\n=== Abuse Contacts ===")
    try:
        abuse_lines = [line for line in result.splitlines()
                       if any(word in line.lower() for word in ['abuse', 'contact', 'email'])]
        if abuse_lines:
            for line in sorted(set(abuse_lines)):
                log(line)
        else:
            log("[-] No abuse contacts found")
    except:
        log("[-] Failed to parse abuse contacts")

    # Reporting links
    log("\n=== Report This Phishing Site ===")
    log("- Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/")
    log("- APWG Report Phishing: https://apwg.org/reportphishing/")
    log("- Microsoft Report Phishing: https://www.microsoft.com/en-us/wphish/")
    log("- VirusTotal: https://www.virustotal.com/gui/domain/" + hostname)
    log("- URLScan: https://urlscan.io/domain/" + hostname)
    log("- crt.sh: https://crt.sh/?q=" + hostname)
    log("- AbuseIPDB: https://www.abuseipdb.com/check/" + hostname)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        run_ultra_recon(target)
    else:
        target = input("Enter domain or URL: ").strip()
        run_ultra_recon(target)
