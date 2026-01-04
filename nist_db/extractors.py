"""Extractors for vendor, CWE, CVSS, and other vulnerability information."""

from typing import List, Dict, Optional, Set


def parse_cpe_vendor(cpe_string: str) -> Optional[str]:
    """extract vendor from CPE string.
    CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    if not cpe_string or not cpe_string.startswith("cpe:"):
        return None
    
    parts = cpe_string.split(":")
    if len(parts) >= 4:
        return parts[3]  # vendor is the 4th part (index 3)
    return None


def extract_vendors_from_configurations(configurations: List[Dict]) -> Set[str]:
    """extract all unique vendors from CVE configurations."""
    vendors = set()
    
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_match = node.get("cpeMatch", [])
            for cpe in cpe_match:
                criteria = cpe.get("criteria", "")
                vendor = parse_cpe_vendor(criteria)
                if vendor and vendor != "*":
                    vendors.add(vendor)
    
    return vendors


def extract_vendors_from_description(description: str) -> Set[str]:
    """extract vendor names from CVE description using keyword matching."""
    vendors = set()
    description_lower = description.lower()
    
    # known drone/autopilot vendors and products
    vendor_keywords = {
        "ardupilot": "ardupilot",
        "apm": "ardupilot",  # ArduPilot Mission Planner
        "pixhawk": "pixhawk",
        "px4": "px4",
        "dji": "dji",
        "phantom": "dji",
        "mavic": "dji",
        "parrot": "parrot",
        "bebop": "parrot",
        "anafi": "parrot",
        "3dr": "3dr",
        "solo": "3dr",
        "yuneec": "yuneec",
        "typhoon": "yuneec",
        "auterion": "auterion",
        "skydio": "skydio",
        "whm autopilot": "whm_autopilot",  # WHM AutoPilot (web hosting, but matches keyword)
        "autopilot": "autopilot_generic",
    }
    
    for keyword, vendor_name in vendor_keywords.items():
        if keyword in description_lower:
            vendors.add(vendor_name)
    
    return vendors


def extract_vendors_from_references(cve: Dict) -> Set[str]:
    """extract vendor information from CVE references."""
    vendors = set()
    references = cve.get("references", [])
    
    for ref in references:
        url = ref.get("url", "").lower()
        # check URLs for vendor names
        vendor_keywords = {
            "ardupilot": "ardupilot",
            "px4": "px4",
            "dji": "dji",
            "parrot": "parrot",
            "3dr": "3dr",
            "yuneec": "yuneec",
        }
        
        for keyword, vendor_name in vendor_keywords.items():
            if keyword in url:
                vendors.add(vendor_name)
    
    return vendors


def extract_cvss_base_scores(metrics: Dict) -> Dict:
    """extract CVSS base scores from all versions."""
    cvss_scores = {}
    
    # CVSS v3.1
    if "cvssMetricV31" in metrics:
        for metric in metrics["cvssMetricV31"]:
            if metric.get("type") == "Primary":
                cvss_data = metric.get("cvssData", {})
                cvss_scores["v3.1"] = {
                    "version": "3.1",
                    "baseScore": cvss_data.get("baseScore"),
                    "baseSeverity": cvss_data.get("baseSeverity"),
                    "vectorString": cvss_data.get("vectorString"),
                }
    
    # CVSS v3.0
    if "cvssMetricV30" in metrics:
        for metric in metrics["cvssMetricV30"]:
            if metric.get("type") == "Primary":
                cvss_data = metric.get("cvssData", {})
                cvss_scores["v3.0"] = {
                    "version": "3.0",
                    "baseScore": cvss_data.get("baseScore"),
                    "baseSeverity": cvss_data.get("baseSeverity"),
                    "vectorString": cvss_data.get("vectorString"),
                }
    
    # CVSS v2.0
    if "cvssMetricV2" in metrics:
        for metric in metrics["cvssMetricV2"]:
            if metric.get("type") == "Primary":
                cvss_data = metric.get("cvssData", {})
                cvss_scores["v2.0"] = {
                    "version": "2.0",
                    "baseScore": cvss_data.get("baseScore"),
                    "baseSeverity": metric.get("baseSeverity"),
                    "vectorString": cvss_data.get("vectorString"),
                }
    
    return cvss_scores


def is_network_related(vuln_data: Dict) -> bool:
    """check if vulnerability is network-related based on CVSS attack vector."""
    # metrics are inside cve object in NIST API v2.0
    cve = vuln_data.get("cve", {})
    metrics = cve.get("metrics", {})
    
    # check CVSS v3.x
    for version in ["cvssMetricV31", "cvssMetricV30"]:
        if version in metrics:
            for metric in metrics[version]:
                if metric.get("type") == "Primary":
                    cvss_data = metric.get("cvssData", {})
                    if cvss_data.get("attackVector") == "NETWORK":
                        return True
    
    # check CVSS v2.0
    if "cvssMetricV2" in metrics:
        for metric in metrics["cvssMetricV2"]:
            if metric.get("type") == "Primary":
                cvss_data = metric.get("cvssData", {})
                if cvss_data.get("accessVector") == "NETWORK":
                    return True
    
    # check description for network keywords
    descriptions = vuln_data.get("cve", {}).get("descriptions", [])
    network_keywords = ["network", "remote", "tcp", "udp", "http", "https", "socket", "connection"]
    for desc in descriptions:
        desc_text = desc.get("value", "").lower()
        if any(keyword in desc_text for keyword in network_keywords):
            return True
    
    return False


def is_sensor_related(vuln_data: Dict) -> bool:
    """check if vulnerability is sensor-related."""
    descriptions = vuln_data.get("cve", {}).get("descriptions", [])
    sensor_keywords = ["sensor", "gps", "imu", "accelerometer", "gyroscope", "magnetometer", 
                       "barometer", "compass", "lidar", "radar", "camera", "telemetry"]
    
    for desc in descriptions:
        desc_text = desc.get("value", "").lower()
        if any(keyword in desc_text for keyword in sensor_keywords):
            return True
    
    return False

