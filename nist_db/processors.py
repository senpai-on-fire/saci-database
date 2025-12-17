"""Vulnerability processing functions."""

from typing import List, Dict, Optional
from extractors import (
    extract_vendors_from_configurations,
    extract_vendors_from_description,
    extract_vendors_from_references,
    extract_cvss_base_scores,
    is_network_related,
    is_sensor_related
)
from mitre_api import extract_cwe_info_enhanced, fetch_capec_for_cwe


def process_vulnerability(vuln_data: Dict) -> Optional[Dict]:
    """process a single vulnerability and extract required information."""
    cve = vuln_data.get("cve", {})
    cve_id = cve.get("id")
    
    if not cve_id:
        return None
    
    # get description first (needed for fallback vendor extraction)
    descriptions = cve.get("descriptions", [])
    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
    
    # extract vendors - try multiple methods
    vendors = set()
    
    # method 1: extract from CPE configurations (most reliable)
    configurations = vuln_data.get("configurations", [])
    vendors.update(extract_vendors_from_configurations(configurations))
    
    # method 2: extract from description (fallback for older CVEs)
    if not vendors and description:
        vendors.update(extract_vendors_from_description(description))
    
    # method 3: extract from references (additional fallback)
    if not vendors:
        vendors.update(extract_vendors_from_references(cve))
    
    # extract CWE with names
    weaknesses = cve.get("weaknesses", [])
    cwe_list = extract_cwe_info_enhanced(weaknesses)
    
    # extract CAPEC for each CWE
    capec_list = []
    for cwe in cwe_list:
        capecs = fetch_capec_for_cwe(cwe["id"])
        capec_list.extend(capecs)
    
    # extract CVSS scores (metrics are inside cve object in NIST API v2.0)
    metrics = cve.get("metrics", {})
    cvss_scores = extract_cvss_base_scores(metrics)
    
    # check if network/sensor related
    is_network = is_network_related(vuln_data)
    is_sensor = is_sensor_related(vuln_data)
    
    return {
        "cve_id": cve_id,
        "description": description,
        "vendors": list(vendors),
        "cwe": cwe_list,
        "capec": capec_list,
        "cvss": cvss_scores,
        "is_network_related": is_network,
        "is_sensor_related": is_sensor,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }


def process_vulnerabilities(vulnerabilities: List[Dict]) -> List[Dict]:
    """process a list of vulnerabilities."""
    processed_vulns = []
    for vuln in vulnerabilities:
        processed = process_vulnerability(vuln)
        if processed:
            processed_vulns.append(processed)
    return processed_vulns

