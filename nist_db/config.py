"""Configuration for NIST CVE crawler pipeline."""

import os

# NIST NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

# rate limiting: NIST allows 5 requests per 30 seconds without API key, 50 with key
# without key: 5 req/30s = 6s delay (safe: 7s to account for processing time)
# with key: 50 req/30s = 0.6s delay (safe: 0.7s)
RATE_LIMIT_DELAY = 7.0 if not NVD_API_KEY else 0.7

# MITRE API Configuration
MITRE_CAPEC_API = "https://capec.mitre.org/data/xml/capec_v3.9.xml"
MITRE_CWE_API = "https://cwe.mitre.org/data/xml/cwec_latest.xml"
MITRE_CWE_JSON = "https://cwe.mitre.org/data/json/cwe_latest.json.zip"

# enable CAPEC extraction (set to False to skip for faster processing)
ENABLE_CAPEC_EXTRACTION = True

# enable CWE name fetching from MITRE (set to False to skip for faster processing)
# if disabled, CWE names will just be the CWE ID itself
ENABLE_CWE_NAME_FETCH = True

# default search keywords for autopilot and drone vendors
DEFAULT_SEARCH_KEYWORDS = [
    "autopilot",
    "drone",
    "quadcopter",
    "uav",
    "ardupilot",
    "px4",
    "dji",
    "parrot",
    "3dr"
]

# default max results per search
DEFAULT_MAX_RESULTS = 500

