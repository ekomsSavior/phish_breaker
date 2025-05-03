import subprocess
import datetime
import os
import re
import requests

def run_curl_head(url):
    try:
        result = subprocess.check_output(['curl', '-I', url], text=True)
        print("[+] curl -I output:\n", result)
        return result
    except Exception as e:
        print(f"[!] curl -I error: {e}")
        return ""

def get_final_url(url):
    try:
        result = subprocess.check_output(['curl', '-Ls', '-o', '/dev/null', '-w', '%{url_effective}', url], text=True)
        print(f"[+] Final URL: {result}")
        return result.strip()
    except Exception as e:
        print(f"[!] curl final URL error: {e}")
        return url

def extract_domain(final_url):
    try:
        result = subprocess.check_output(f'echo "{final_url}" | awk -F/ \'{{print $3}}\'', shell=True, text=True)
        print(f"[+] Extracted domain: {result}")
        return result.strip()
    except Exception as e:
        print(f"[!] awk domain extract error: {e}")
        return ""

def extract_path(final_url):
    try:
        parts = final_url.split("/", 3)
        path = "/" + parts[3] if len(parts) > 3 else "/"
        print(f"[+] Extracted path: {path}")
        return path
    except Exception as e:
        print(f"[!] Path extract error: {e}")
        return ""

def extract_hidden_domains(url):
    try:
        response = requests.get(url, timeout=10)
        html = response.text
        found = re.findall(r'https?://[^\s\'"]+', html)
        unique_domains = sorted(set(found))
        print("[+] Hidden domains in page body:")
        for d in unique_domains:
            print(f"- {d}")
        return unique_domains
    except Exception as e:
        print(f"[!] Hidden domain extraction error: {e}")
        return []

def save_report(short_url, curl_head, final_url, domain, path, hidden_domains):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_name = f"{report_dir}/report_unshorten_{timestamp}.txt"
    with open(report_name, "w") as f:
        f.write(f"Shortened URL: {short_url}\n\n")
        f.write("curl -I output:\n")
        f.write(curl_head + "\n")
        f.write(f"Final URL: {final_url}\n")
        f.write(f"Extracted Domain: {domain}\n")
        f.write(f"Extracted Path: {path}\n")
        if hidden_domains:
            f.write("\nHidden domains in page body:\n")
            for d in hidden_domains:
                f.write(f"- {d}\n")
    print(f"[+] Saved report as {report_name}")

if __name__ == "__main__":
    short_url = input("Enter shortened URL: ").strip()
    curl_head = run_curl_head(short_url)
    final_url = get_final_url(short_url)
    domain = extract_domain(final_url)
    path = extract_path(final_url)
    hidden_domains = extract_hidden_domains(final_url)
    save_report(short_url, curl_head, final_url, domain, path, hidden_domains)
