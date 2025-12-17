"""MITRE API client for fetching CWE names and CAPEC attack patterns."""

import requests
import xml.etree.ElementTree as ET
import zipfile
import io
from typing import List, Dict
from config import MITRE_CAPEC_API, MITRE_CWE_API, ENABLE_CAPEC_EXTRACTION, ENABLE_CWE_NAME_FETCH

# cache for CWE names and CAPEC data
cwe_name_cache = {}
cwe_database = {}  # full CWE database loaded from MITRE
capec_cache = {}
capec_cwe_mapping = {}
_capec_download_attempted = False  # flag to prevent multiple download attempts
_cwe_download_attempted = False  # flag to prevent multiple download attempts

# fallback CWE names dictionary
_FALLBACK_CWE_NAMES = {
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-326": "Inadequate Encryption Strength",
}


def _normalize_cwe_id(cwe_id: str, add_prefix: bool = True) -> str:
    """normalize CWE ID format (e.g., "79" -> "CWE-79" or "CWE-79" -> "79")."""
    cwe_id = cwe_id.strip()
    if add_prefix:
        if not cwe_id.startswith('CWE-'):
            return f"CWE-{cwe_id}"
        return cwe_id
    else:
        if cwe_id.startswith('CWE-'):
            return cwe_id[4:]
        return cwe_id


def _parse_xml_from_response(response: requests.Response, is_zip: bool = False) -> ET.Element:
    """parse XML from HTTP response, handling ZIP files and BOM."""
    content = response.content
    
    # extract from ZIP if needed
    if is_zip:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zip_file:
                xml_files = [f for f in zip_file.namelist() if f.endswith('.xml')]
                if not xml_files:
                    raise ValueError("No XML file found in ZIP archive")
                content = zip_file.read(xml_files[0])
                print(f"Extracted {xml_files[0]} from ZIP archive")
        except zipfile.BadZipFile:
            pass  # not a ZIP, use content as-is
    
    # remove BOM if present
    if content.startswith(b'\xef\xbb\xbf'):
        content = content[3:]
    
    return ET.fromstring(content)


def _extract_namespace(root: ET.Element, default_ns: str) -> dict:
    """extract namespace from root element."""
    ns = {}
    ns_key = default_ns.split('/')[-1].split('-')[0]  # extract 'cwe' or 'capec'
    if root.tag.startswith('{'):
        ns_uri = root.tag[1:].split('}')[0]
        ns[ns_key] = ns_uri
    else:
        ns[ns_key] = default_ns
    return ns


def _find_elements_with_fallback(root: ET.Element, element_name: str, ns: dict, ns_key: str) -> list:
    """find XML elements with namespace fallback."""
    elements = []
    if ns.get(ns_key):
        elements = root.findall(f'.//{{{ns[ns_key]}}}{element_name}')
    if not elements:
        elements = root.findall(f'.//{element_name}')
    return elements


def _load_cwe_database():
    """load CWE database from MITRE XML API."""
    global _cwe_download_attempted, cwe_database
    
    if _cwe_download_attempted:
        return
    
    _cwe_download_attempted = True
    
    try:
        print(f"Downloading CWE data from MITRE...")
        response = requests.get(MITRE_CWE_API, timeout=30)
        response.raise_for_status()
        
        root = _parse_xml_from_response(response, is_zip=True)
        ns = _extract_namespace(root, 'http://cwe.mitre.org/cwe-6')
        weaknesses = _find_elements_with_fallback(root, 'Weakness', ns, 'cwe')
        
        # try alternative if no weaknesses found
        if not weaknesses:
            for elem in root.iter():
                if elem.get('ID') and 'weakness' in elem.tag.lower():
                    weaknesses.append(elem)
        
        for weakness in weaknesses:
            cwe_id_attr = weakness.get('ID')
            cwe_name_attr = weakness.get('Name')
            
            # try getting name from child element if not in attributes
            if not cwe_name_attr:
                name_elem = weakness.find('.//Name')
                if name_elem is not None:
                    cwe_name_attr = name_elem.text
            
            if cwe_id_attr:
                cwe_id = _normalize_cwe_id(cwe_id_attr)
                cwe_name = cwe_name_attr.strip() if cwe_name_attr else cwe_id
                cwe_database[cwe_id] = cwe_name
        
        if not cwe_database:
            raise ValueError("No CWE entries found in XML response")
        print(f"Loaded {len(cwe_database)} CWE entries from MITRE database")
        
    except Exception as e:
        print(f"Warning: Could not fetch/parse CWE data: {e}")
        print("Will use fallback dictionary for CWE names")
        cwe_database.update(_FALLBACK_CWE_NAMES)


def fetch_cwe_name(cwe_id: str) -> str:
    """fetch CWE name from MITRE CWE database.
    Downloads and parses CWE XML to get the name for the given CWE ID.
    Falls back to CWE ID if name not found or if CWE name fetching is disabled.
    """
    # skip MITRE API call if disabled
    if not ENABLE_CWE_NAME_FETCH:
        return cwe_id
    
    # ensure database is loaded
    if not _cwe_download_attempted:
        _load_cwe_database()
    
    # check cache first
    if cwe_id in cwe_name_cache:
        return cwe_name_cache[cwe_id]
    
    # look up in database
    cwe_name = cwe_database.get(cwe_id, cwe_id)  # fallback to ID if not found
    
    # cache the result
    cwe_name_cache[cwe_id] = cwe_name
    return cwe_name


def fetch_capec_for_cwe(cwe_id: str) -> List[Dict]:
    """fetch CAPEC attack patterns related to a CWE from MITRE CAPEC database.
    Downloads and parses CAPEC XML to find patterns that reference the given CWE.
    Returns empty list if CAPEC extraction is disabled.
    """
    global _capec_download_attempted
    
    # skip CAPEC extraction if disabled
    if not ENABLE_CAPEC_EXTRACTION:
        return []
    
    if cwe_id in capec_cache:
        return capec_cache[cwe_id]
    
    capec_list = []
    
    # download CAPEC XML only once
    if not _capec_download_attempted:
        _capec_download_attempted = True
        try:
            print(f"Downloading CAPEC data from MITRE...")
            response = requests.get(MITRE_CAPEC_API, timeout=30)
            response.raise_for_status()
            
            root = _parse_xml_from_response(response, is_zip=False)
            ns = _extract_namespace(root, 'http://capec.mitre.org/capec-3')
            attack_patterns = _find_elements_with_fallback(root, 'Attack_Pattern', ns, 'capec')
            
            for attack_pattern in attack_patterns:
                capec_id_attr = attack_pattern.get('ID')
                capec_name_attr = attack_pattern.get('Name')
                
                if capec_id_attr and capec_name_attr:
                    capec_id = f"CAPEC-{capec_id_attr.strip()}"
                    capec_name = capec_name_attr.strip()
                    
                    related_weaknesses = _find_elements_with_fallback(
                        attack_pattern, 'Related_Weakness', ns, 'capec'
                    )
                    
                    for weakness in related_weaknesses:
                        cwe_id_attr = weakness.get('CWE_ID')
                        if cwe_id_attr:
                            related_cwe = _normalize_cwe_id(cwe_id_attr, add_prefix=False)
                            if related_cwe not in capec_cwe_mapping:
                                capec_cwe_mapping[related_cwe] = []
                            capec_cwe_mapping[related_cwe].append({
                                "id": capec_id,
                                "name": capec_name
                            })
            
            print(f"Loaded {len(capec_cwe_mapping)} CWE mappings from CAPEC database")
            
        except Exception as e:
            print(f"Warning: Could not fetch/parse CAPEC data: {e}")
            print("Will use fallback mappings for all CWEs")
    
    # look up CAPEC patterns for this CWE
    cwe_num = _normalize_cwe_id(cwe_id, add_prefix=False)
    capec_list = capec_cwe_mapping.get(cwe_num, [])
    
    capec_cache[cwe_id] = capec_list
    return capec_list


def extract_cwe_info_enhanced(weaknesses: List[Dict]) -> List[Dict]:
    """extract CWE ID and name from weaknesses."""
    cwe_list = []
    
    for weakness in weaknesses:
        descriptions = weakness.get("description", [])
        for desc in descriptions:
            cwe_id = desc.get("value", "")
            if cwe_id.startswith("CWE-"):
                cwe_name = fetch_cwe_name(cwe_id)
                cwe_list.append({
                    "id": cwe_id,
                    "name": cwe_name,
                })
    
    return cwe_list

