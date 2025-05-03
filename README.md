# Phish Breaker

**Phish Breaker** — smashing scams one link at a time.

## Tools Included

- **unshorten_and_extract.py** → Expand shortlinks, extract domains, extract path, detect hidden domains in page body, and save detailed reports  
- **bucket_sweeper.py** → List `.html` phishing files in Google Cloud buckets  
- **target_recon.py** → Resolve IP, run WHOIS, Nmap, and headers scan  
- **scanner.py** → Collect WHOIS, DNS, and abuse contact info  
- **deep_recon.py** → Perform full forensic scan (redirects, SSL, forms, metadata, Shodan, VirusTotal, DIRB)

---

##  Recommended Workflow

1. `unshorten_and_extract.py` → Unwrap shortlinks, extract domain, path, and scrape hidden links  
2. `bucket_sweeper.py` → Sweep Google buckets for `.html` phishing files  
3. `target_recon.py` → Resolve + scan target domain and IP  
4. `scanner.py` → Get registrar + abuse contact details and links for reporting phishing. 
5. `deep_recon.py` → Perform deep forensic analysis (redirects, SSL, forms, metadata, Shodan, VirusTotal)

You can stop after step 3 for a quick sweep, or run all tools for a full forensic report.

---

## Setup

1. Clone the repo
   ```bash
   git clone https://github.com/ekomsSavior/phish_breaker.git
   cd phish_breaker
   ```

2. Install dependencies 
   ```bash
   # requests for Python scripts
   sudo apt install python3-requests

   # curl, nmap, whois, dirb (if not already installed)
   sudo apt install curl nmap whois dirb
   ```

3. The `reports/` folder is already included in the repo — all reports will be saved there.

---

##  Usage

Run any tool directly
```bash
python3 unshorten_and_extract.py
python3 bucket_sweeper.py
python3 target_recon.py
python3 scanner.py
python3 deep_recon.py
```

All `.txt` reports will be saved inside the `reports/` folder with timestamps for easy case tracking.

---

## DISCLAIMER 

This tool is for ethical research.    
Always report phishing domains, hosts, and infrastructure to relevant authorities, CERT teams, and hosting providers.
If you run a scanner.py scan there will be links for reporting to the proper places. xo


