# Phish Breaker

**Phish Breaker** — smashing scams one link at a time.

## Tools Included

- **unshorten_and_extract.py** → Expand shortlinks, extract domains, extract path, detect hidden domains in page body, and save detailed reports  
- **bucket_sweeper.py** → Sweep Google Cloud buckets for live phishing files, extract hidden domains, and document forensic evidence.  
- **ultra_recon.py** → Perform combined WHOIS, DNS, SSL, headers, forms, metadata, Shodan, VirusTotal, Nmap, DIRB, and abuse contact collection — full forensic recon in one run.

---

#  Example: Shortened Link

Third-party shortener/Public shortlink (s.id, bit.ly, tinyurl)

```
https://s.id/advertising_sort_policy_contact_39574911/89247116/15424
```

Twitter Platform shortlink in SMS phishing

```
https://t.co/Zl1SIkqqh2j
```

Reveal the real domain with: `unshorten_and_extract.py`

---

#  Example: Google Bucket Link with File

```
https://storage.googleapis.com/cx0kk2cc1w2c1wc2xw1cw/rmPc53277.html
```

Sweep with: `bucket_sweeper.py`

---

## Recommended Workflow

1. `unshorten_and_extract.py` → Unwrap shortlinks, extract domain, path, and scrape hidden links  
2. `bucket_sweeper.py` → Sweep Google buckets for `.html` phishing files  
3. `ultra_recon.py` → Perform deep forensic analysis (WHOIS, abuse, headers, SSL, forms, metadata, Shodan, VirusTotal, Nmap, DIRB, reporting links)

You can stop after step 2 for a fast sweep or run all the way through for a full forensic report.

BONUS: go over to PHISH_HUNTER_PRO and have fun with the disruption tools over there xo 

https://github.com/ekomsSavior/PHISH_HUNTER_PRO

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

4.  Add your API keys: optional-

If you want to enable Shodan and VirusTotal lookups, open `ultra_recon.py` and paste in your API keys:

```python
SHODAN_API_KEY = "your_shodan_api_key_here"
VT_API_KEY = "your_virustotal_api_key_here"
```

Without keys, those sections will gracefully skip during scans.


---

## Usage

Run any tool directly
```bash
python3 unshorten_and_extract.py
python3 bucket_sweeper.py                  # or
python3 bucket_sweeper.py --wordlist mylist.txt
python3 ultra_recon.py
```

All `.txt` reports will be saved inside the `reports/` folder with timestamps for easy case tracking.

---

#### Tips

IN BUCKET SWEEPER:

- Always include the **trailing slash** if you want it to sweep like a folder
  ```
  https://storage.googleapis.com/examplebucket/
  ```

- You can also target a specific file
  ```
  https://storage.googleapis.com/examplebucket/rmdc77.html
  ```

BONUS: disruption tools-

https://github.com/ekomsSavior/PHISH_HUNTER_PRO


---

## DISCLAIMER

This tool is for ethical research.    
Always report phishing domains, hosts, and infrastructure to relevant authorities, CERT teams, and hosting providers.  
If you run an `ultra_recon.py` scan, there will be abuse contacts + reporting links included at the end of the report.

xo 💜 
