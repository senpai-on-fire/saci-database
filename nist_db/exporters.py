"""Export and statistics functions."""

import json
from datetime import datetime
from typing import List, Dict


def export_to_json(processed_vulns: List[Dict], matched_vulns: List[Dict], 
                   search_keywords: List[str], output_file: str = "nist_cve_results.json") -> str:
    """export results to JSON file."""
    results = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_cves_found": len(processed_vulns),
            "total_matches": len(matched_vulns),
            "search_keywords": search_keywords
        },
        "vulnerabilities": processed_vulns,
        "saci_matches": matched_vulns
    }
    
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    return output_file


def generate_statistics(processed_vulns: List[Dict]) -> Dict:
    """generate summary statistics from processed vulnerabilities."""
    stats = {}
    
    # vendor distribution
    vendor_counts = {}
    for vuln in processed_vulns:
        for vendor in vuln.get("vendors", []):
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
    
    stats["vendor_counts"] = vendor_counts
    stats["top_vendors"] = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # CWE distribution
    cwe_counts = {}
    for vuln in processed_vulns:
        for cwe in vuln.get("cwe", []):
            cwe_id = cwe["id"]
            cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
    
    stats["cwe_counts"] = cwe_counts
    stats["top_cwes"] = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # CVSS distribution
    cvss_scores = []
    for vuln in processed_vulns:
        for version, cvss_data in vuln.get("cvss", {}).items():
            score = cvss_data.get("baseScore")
            if score:
                cvss_scores.append(score)
    
    if cvss_scores:
        stats["cvss_stats"] = {
            "average": sum(cvss_scores) / len(cvss_scores),
            "min": min(cvss_scores),
            "max": max(cvss_scores),
            "critical": sum(1 for s in cvss_scores if s >= 9.0),
            "high": sum(1 for s in cvss_scores if 7.0 <= s < 9.0),
            "medium": sum(1 for s in cvss_scores if 4.0 <= s < 7.0),
            "low": sum(1 for s in cvss_scores if s < 4.0),
        }
    else:
        stats["cvss_stats"] = None
    
    # network/sensor breakdown
    network_count = sum(1 for v in processed_vulns if v.get("is_network_related"))
    sensor_count = sum(1 for v in processed_vulns if v.get("is_sensor_related"))
    both_count = sum(1 for v in processed_vulns if v.get("is_network_related") and v.get("is_sensor_related"))
    
    stats["categories"] = {
        "network_related": network_count,
        "sensor_related": sensor_count,
        "both": both_count
    }
    
    return stats


def print_statistics(stats: Dict):
    """print statistics in a readable format."""
    print("\n" + "=" * 60)
    print("Summary Statistics:")
    print("=" * 60)
    
    print(f"\nTop 10 Vendors:")
    for vendor, count in stats["top_vendors"]:
        print(f"  {vendor}: {count}")
    
    print(f"\nTop 10 CWEs:")
    for cwe_id, count in stats["top_cwes"]:
        print(f"  {cwe_id}: {count}")
    
    if stats["cvss_stats"]:
        cvss = stats["cvss_stats"]
        print(f"\nCVSS Score Statistics:")
        print(f"  Average: {cvss['average']:.2f}")
        print(f"  Min: {cvss['min']:.2f}")
        print(f"  Max: {cvss['max']:.2f}")
        print(f"  Critical (>=9.0): {cvss['critical']}")
        print(f"  High (7.0-8.9): {cvss['high']}")
        print(f"  Medium (4.0-6.9): {cvss['medium']}")
        print(f"  Low (<4.0): {cvss['low']}")
    
    categories = stats["categories"]
    print(f"\nVulnerability Categories:")
    print(f"  Network-related: {categories['network_related']}")
    print(f"  Sensor-related: {categories['sensor_related']}")
    print(f"  Both: {categories['both']}")

