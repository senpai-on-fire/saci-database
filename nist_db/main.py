"""Main pipeline entry point for NIST CVE crawler."""

from nist_api import search_nist_cves
from processors import process_vulnerabilities
from config import DEFAULT_SEARCH_KEYWORDS, DEFAULT_MAX_RESULTS, ENABLE_CAPEC_EXTRACTION, ENABLE_CWE_NAME_FETCH


def main():
    print("Starting NIST CVE crawl...")
    print("=" * 60)
    
    # track all vulnerabilities across all searches
    all_vulnerabilities = []
    seen_cve_ids = set()
    all_keyword_results = {}
    search_count = 0
    
    # main search loop - keep asking for searches until user wants to stop
    while True:
        search_count += 1
        print(f"\n[Search Session {search_count}]")
        print("=" * 60)
        
        # get search keywords from user (searches across descriptions, vendors, products, etc.)
        print("\nEnter search keywords (comma-separated, or press Enter for default keywords):")
        print("  (searches in CVE descriptions, vendor names, product names, and references)")
        user_input = input("> ").strip()
        
        # use default keywords if user just presses enter
        if not user_input:
            search_keywords = DEFAULT_SEARCH_KEYWORDS
            print(f"Using default keywords: {', '.join(search_keywords)}")
        else:
            # parse comma-separated keywords
            search_keywords = [kw.strip() for kw in user_input.split(",") if kw.strip()]
            if not search_keywords:
                print("No valid keywords entered. Using default keywords.")
                search_keywords = DEFAULT_SEARCH_KEYWORDS
        
        print(f"\nSearching with {len(search_keywords)} keyword(s)...")
        print("=" * 60)
        
        # iterate through each keyword and search separately
        keyword_results = {}
        
        for idx, keyword in enumerate(search_keywords, 1):
            print(f"\n[Keyword {idx}/{len(search_keywords)}]")
            # search for this specific keyword
            keyword_vulns = search_nist_cves([keyword], max_results=DEFAULT_MAX_RESULTS)
            
            # track unique CVEs found by this keyword
            new_vulns = []
            for vuln in keyword_vulns:
                cve_id = vuln.get("cve", {}).get("id")
                if cve_id and cve_id not in seen_cve_ids:
                    seen_cve_ids.add(cve_id)
                    all_vulnerabilities.append(vuln)
                    new_vulns.append(vuln)
            
            keyword_results[keyword] = {
                "total_found": len(keyword_vulns),
                "new_unique": len(new_vulns)
            }
            all_keyword_results[keyword] = keyword_results[keyword]
            print(f"  Keyword '{keyword}': {len(keyword_vulns)} results, {len(new_vulns)} new unique CVEs")
        
        # show summary for this search session
        print(f"\n[Search Session {search_count} Summary]")
        print("=" * 60)
        print(f"Total unique CVEs found in this session: {sum(r['new_unique'] for r in keyword_results.values())}")
        print(f"Total unique CVEs across all searches: {len(all_vulnerabilities)}")
        
        # ask if user wants to do another search
        print("\nDo you want to perform another search? (y/n, or 'process' to process and display results):")
        user_choice = input("> ").strip().lower()
        
        if user_choice == 'n' or user_choice == 'no':
            break
        elif user_choice == 'process' or user_choice == 'p':
            break
    
    # check if we have any vulnerabilities to process
    if not all_vulnerabilities:
        print("\nNo vulnerabilities found. Exiting.")
        return
    
    # use aggregated vulnerabilities
    vulnerabilities = all_vulnerabilities
    
    print(f"\n[Final Summary]")
    print("=" * 60)
    print(f"Total unique CVEs found across all searches: {len(vulnerabilities)}")
    print(f"Total search sessions: {search_count}")
    
    # show summary by keyword
    print("\nSearch summary by keyword:")
    for keyword, stats in all_keyword_results.items():
        print(f"  {keyword}: {stats['total_found']} total, {stats['new_unique']} unique")
    print("=" * 60)
    
    # process vulnerabilities
    print("\nProcessing vulnerabilities...")
    cwe_status = "enabled" if ENABLE_CWE_NAME_FETCH else "disabled (faster)"
    capec_status = "enabled" if ENABLE_CAPEC_EXTRACTION else "disabled (faster)"
    print(f"CWE name fetch: {cwe_status}, CAPEC extraction: {capec_status}")
    print("=" * 60)
    
    processed_vulns = process_vulnerabilities(vulnerabilities)
    
    print(f"\nProcessed {len(processed_vulns)} vulnerabilities")
    print("=" * 60)
    
    # display results
    print("\nResults:")
    for i, vuln in enumerate(processed_vulns):
        print(f"\n{i + 1}. {vuln['cve_id']}")
        print(f"   Vendors: {', '.join(vuln['vendors']) if vuln['vendors'] else 'N/A'}")
        if vuln['cwe']:
            cwe_str = ', '.join([f"{c['id']} ({c['name']})" for c in vuln['cwe']])
            print(f"   CWE: {cwe_str}")
        if vuln['capec']:
            capec_str = ', '.join([f"{c['id']} ({c['name']})" for c in vuln['capec']])
            print(f"   CAPEC: {capec_str}")
        if vuln['cvss']:
            best_cvss = max(vuln['cvss'].values(), key=lambda x: x.get('baseScore', 0))
            print(f"   CVSS: {best_cvss.get('baseScore')} ({best_cvss.get('version')})")
        print(f"   Network: {vuln['is_network_related']}, Sensor: {vuln['is_sensor_related']}")
        print(f"   Description: {vuln['description'][:100]}...")


if __name__ == "__main__":
    main()

