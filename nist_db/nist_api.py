"""NIST NVD API client for searching and fetching CVE data."""

import requests
import time
from typing import List, Dict
from config import NVD_API_URL, headers, RATE_LIMIT_DELAY


def _make_request_with_retry(url: str, headers: dict, params: dict, max_retries: int = 3) -> requests.Response:
    """make HTTP request with retry logic for rate limiting."""
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            # handle rate limiting (429)
            if response.status_code == 429:
                # check for Retry-After header
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    # use retry-after time, but ensure it's at least our configured delay
                    wait_time = max(int(retry_after) + 1, RATE_LIMIT_DELAY * 2)
                else:
                    # use exponential backoff based on our rate limit delay
                    wait_time = RATE_LIMIT_DELAY * (2 ** (attempt + 1))
                
                if attempt < max_retries - 1:
                    print(f"  Rate limited. Waiting {wait_time:.1f} seconds before retry...")
                    time.sleep(wait_time)
                    continue
                else:
                    response.raise_for_status()
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                wait_time = 10 * (attempt + 1)  # 10s, 20s, 30s
                print(f"  Request failed: {e}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                raise
    
    raise requests.exceptions.RequestException("Max retries exceeded")


def search_nist_cves(keywords: List[str], max_results: int = 200) -> List[Dict]:
    """search NIST CVE database with multiple keywords."""
    all_vulnerabilities = []
    seen_cve_ids = set()
    
    for keyword in keywords:
        print(f"Searching for: {keyword}")
        start_index = 0
        results_per_page = 200  # max allowed by API
        
        while start_index < max_results:
            params = {
                "keywordSearch": keyword,
                "startIndex": start_index,
                "resultsPerPage": min(results_per_page, max_results - start_index)
            }
            
            try:
                response = _make_request_with_retry(NVD_API_URL, headers, params)
                data = response.json()
                
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cve", {}).get("id")
                    if cve_id and cve_id not in seen_cve_ids:
                        seen_cve_ids.add(cve_id)
                        all_vulnerabilities.append(vuln)
                
                total_results = data.get("totalResults", 0)
                print(f"  Found {len(vulnerabilities)} results (total: {total_results})")
                
                start_index += len(vulnerabilities)
                
                # check if we've reached the end or max_results
                if start_index >= total_results or start_index >= max_results:
                    break
                
                # rate limiting between pagination requests (skip on last page)
                time.sleep(RATE_LIMIT_DELAY)
                
            except requests.exceptions.RequestException as e:
                print(f"Error fetching data for '{keyword}': {e}")
                break
    
    return all_vulnerabilities

