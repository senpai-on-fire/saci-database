# NIST CVE Crawler - Usage Guide

Simple guide to use the NIST CVE crawler pipeline.

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the crawler:**
   ```bash
   python main.py
   ```

3. **Interactive search:**
   - When prompted, enter search keywords (comma-separated) or press Enter to use default keywords
   - The crawler searches across CVE descriptions, vendor names, product names, and references
   - After each search session, choose to:
     - Continue with another search (`y`)
     - Process and display results (`n` or `process`/`p`)

## Configuration

Edit `config.py` to customize:

### API Key (Optional but Recommended)
Get a free API key from [NIST NVD](https://nvd.nist.gov/developers/request-an-api-key) to increase rate limits:
- Without key: 5 requests per 30 seconds
- With key: 50 requests per 30 seconds

Set it as environment variable:
```bash
export NVD_API_KEY=your_api_key_here
```

### Search Keywords
You can search interactively by entering keywords when prompted, or modify `DEFAULT_SEARCH_KEYWORDS` in `config.py` for default keywords:
```python
DEFAULT_SEARCH_KEYWORDS = [
    "autopilot",
    "drone",
    "px4",
    # add your keywords here
]
```

**Interactive search examples:**
- Enter `dji, parrot` to search for specific vendors
- Enter `gps, sensor` to search for technologies
- Press Enter to use default keywords
- Keywords are searched across descriptions, vendors, products, and references

### Max Results
Change `DEFAULT_MAX_RESULTS` to limit how many CVEs to fetch per keyword:
```python
DEFAULT_MAX_RESULTS = 500  # default
```

### Performance Options
Speed up processing by disabling MITRE API calls:

```python
# disable CWE name fetching (uses CWE ID as name)
ENABLE_CWE_NAME_FETCH = False

# disable CAPEC extraction
ENABLE_CAPEC_EXTRACTION = False
```

## Usage Flow

1. **Start the crawler** - runs `python main.py`
2. **Enter keywords** - type comma-separated keywords or press Enter for defaults
3. **View search results** - see how many CVEs were found per keyword
4. **Continue or process** - choose to search again or process all results
5. **View final results** - see processed vulnerabilities with all details

## Output

The crawler prints results to console showing:
- Search session summaries with unique CVE counts
- Final summary across all search sessions
- Detailed results for each CVE:
  - CVE ID
  - Vendors
  - CWE (Common Weakness Enumeration)
  - CAPEC (Common Attack Pattern Enumeration)
  - CVSS scores
  - Network/Sensor related flags
  - Description

## Rate Limiting

The crawler automatically handles rate limiting:
- Waits between requests to respect NIST limits
- Retries with exponential backoff if rate limited
- Shows status messages during retries

## File Structure

```
nist/
├── main.py           # Entry point - run this
├── config.py         # Configuration settings
├── nist_api.py       # NIST API client
├── mitre_api.py      # MITRE CWE/CAPEC API client
├── extractors.py     # Data extraction functions
├── processors.py     # Vulnerability processing
├── matchers.py       # SACI-DB matching (optional)
└── exporters.py      # Export functions (optional)
```

## Troubleshooting

**Rate limit errors:**
- Get an API key to increase limits
- Increase `RATE_LIMIT_DELAY` in `config.py`
- Reduce `DEFAULT_MAX_RESULTS`

**Slow processing:**
- Set `ENABLE_CWE_NAME_FETCH = False`
- Set `ENABLE_CAPEC_EXTRACTION = False`
- Reduce `DEFAULT_MAX_RESULTS`

**No results found:**
- Check your search keywords
- Verify internet connection
- Check NIST API status

