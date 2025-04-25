import re
from cwe2.database import Database
import requests
from bs4 import BeautifulSoup

db = Database()

def preprocess_cvss_v2(cvss):
    if cvss is None:
        return None
    
    pattern = r'AV:([LAN])\/AC:([HML])\/Au:([MSN])\/C:([NPC])\/I:([NPC])\/A:([NPC])'
    vectors = re.match(pattern, cvss)

    if vectors is None:
        return None
    
    # Mappings for each Vector Value
    attack_vector_map = {'L': 'Local', 'A': 'Adjacent Network', 'N': 'Network'}
    complexity_map = {'H': 'High', 'M': 'Medium', 'L': 'Low'}
    auth_map = {'S': 'Single', 'M': 'Multiple', 'N': 'No'}
    impact_map = {'N': 'no', 'P': 'partial', 'C': 'complete'}
    
    # Retrieve Mapping for Matched Value
    attack_vector = attack_vector_map.get(vectors.group(1), "Unknown")
    access_complexity = complexity_map.get(vectors.group(2), "Unknown")
    authentication = auth_map.get(vectors.group(3), "Unknown")
    confidentiality_impact = impact_map.get(vectors.group(4), "Unknown")
    integrity_impact = impact_map.get(vectors.group(5), "Unknown")
    availability_impact = impact_map.get(vectors.group(6), "Unknown")

    # Construct Natural Lanugage CVSS V2 Description
    return (
        f"The CVE is Exploited by the {attack_vector} Attack Vector.\n"
        f"The CVE has {access_complexity} Attack Complexity.\n"
        f"The CVE requires {authentication} Authentication.\n"
        f"The CVE has {confidentiality_impact} Confidentiality Impact.\n"
        f"The CVE has {integrity_impact} Integrity Impact.\n"
        f"The CVE has {availability_impact} Availability Impact."
    )

def preprocess_cvss_v3x(cvss):
    if cvss is None:
        return None
    
    # Adjusted pattern to account for "CVSS:3.0/" prefix
    pattern = r'CVSS:3\.[01]\/AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([NLH])\/I:([NLH])\/A:([NLH])'
    vectors = re.match(pattern, cvss)

    if vectors is None:
        return None

    # Mappings for each Vector Value
    attack_vector_map = {'N': 'Network', 'A': 'Adjacent Network', 'L': 'Local', 'P': 'Physical'}
    complexity_map = {'L': 'Low', 'H': 'High'}
    privilleges_map = {'N': 'No', 'L': 'Low', 'H': 'High'}
    interaction_map = {'N': 'Does Not Require', 'R': 'Requires'}
    scope_map = {'U': 'Unchanged', 'C': 'Changed'}
    impact_map = {'N': 'No', 'L': 'Low', 'H': 'High'}

    # Retrieve Mapping for Matched Value
    attack_vector = attack_vector_map.get(vectors.group(1), "Unknown")
    attack_complexity = complexity_map.get(vectors.group(2), "Unknown")
    privilleges = privilleges_map.get(vectors.group(3), "Unknown")
    interaction = interaction_map.get(vectors.group(4), "Unknown")
    scope = scope_map.get(vectors.group(5), "Unknown")
    confidentiality_impact = impact_map.get(vectors.group(6), "Unknown")
    integrity_impact = impact_map.get(vectors.group(7), "Unknown")
    availability_impact = impact_map.get(vectors.group(8), "Unknown")

    # Construct Natural Language CVSS V3.x Description
    return(
            f"The CVE is Exploited by the {attack_vector} Attack Vector.\n" 
            f"The CVE has {attack_complexity} Attack Complexity.\n"
            f"The CVE Requires {privilleges} Privilleges.\n"
            f"the CVE {interaction} User Interaction.\n"
            f"The CVE scope is {scope}.\n"
            f"The CVE has {confidentiality_impact} Confidentiality Impact.\n"
            f"The CVE has {integrity_impact} Integrity Impact.\n"
            f"The CVE has {availability_impact} Availability Impact.\n"
        )

def preprocess_cwe_ids(ids):
    if not ids:
        return []
    
    processed_weaknesses = []
    for id in ids:
        if id == "NVD-CWE-noinfo" or id == "NVD-CWE-Other":
            continue
        digits = re.findall(r'\d+', id)
        weakness = db.get(digits[0])
        processed_weaknesses.append(f"The CVE is affected by {weakness.name}: {weakness.description}\n")
        
    return ''.join(processed_weaknesses)

"""
def preprocess_cwe_ids(ids):
    # Simple CWE
    if not ids:
        return []
    
    processed_weaknesses = []
    for id in ids:
        if id == "NVD-CWE-noinfo" or id == "NVD-CWE-Other":
            continue
        digits = re.findall(r'\d+', id)
        weakness = db.get(digits[0])
        processed_weaknesses.append(weakness.name)
        
    return ', '.join(processed_weaknesses)
"""

def preprocess_cpe(cpe):
    if not cpe:
        return "No weakness information known for CVE."
    
    # Define a CPE pattern for parsing
    cpe_pattern = r'cpe:2\.3:([aho]):([^:]+):([^:]+):([^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)'
    
    # Define component type mappings
    component_type_map = {'a': 'Application', 'o': 'Operating System', 'h': 'Hardware'}
    
    # Match the CPE string against the pattern
    match = re.match(cpe_pattern, cpe)
    if not match:
        return "Invalid CPE format."
    
    # Extract matched groups
    component_type_code = match.group(1)  # a, o, h
    vendor_name = match.group(2)          # Vendor
    product_name = match.group(3)         # Product
    
    # Map component type
    component_type = component_type_map.get(component_type_code, "Unknown Component Type")
    
    # Construct a human-readable description without the version
    return f"The CVE affects {vendor_name.capitalize()} {product_name.capitalize()} {component_type}."

def get_capec_title(capec_id):
    url = f"https://capec.mitre.org/data/definitions/{capec_id}.html"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # The title is typically contained in the <title> tag.
        title_tag = soup.find('title')
        if title_tag:
            # The title usually comes in a format like "CAPEC-13 | Some CAPEC Title"
            title_text = title_tag.get_text(strip=True)
            match = re.search(r':\s*(.*?)\s*\(', title_text)
            if match:
                return match.group(1)
        return None

    except Exception as e:
        print(f"Error retrieving CAPEC title for id {capec_id}: {e}")
    return None

# caching mechanism to avoid repeated requests.
_capec_cache = {}

def get_capec_title_cached(capec_id):
    if capec_id in _capec_cache:
        return _capec_cache[capec_id]
    title = get_capec_title(capec_id)
    _capec_cache[capec_id] = title
    return title

def preprocess_capec(cwe_ids):
    if not cwe_ids:
        return ""
    
    capec_titles = set()  # using a set to avoid duplicate titles
    for cwe in cwe_ids:
        if cwe in ["NVD-CWE-noinfo", "NVD-CWE-Other"]:
            continue
        digits = re.findall(r'\d+', cwe)
        if digits:
            # Get the CWE object (weakness)
            weakness = db.get(digits[0])
            if weakness and weakness.related_attack_patterns:
                # The related_attack_patterns field is expected to be in a format like "::13::146::176::..."
                for item in weakness.related_attack_patterns.split("::"):
                    if item.isdigit():
                        capec_title = get_capec_title_cached(item)
                        if capec_title:
                            capec_titles.add(capec_title)
    if not capec_titles:
        return None
    return ', '.join(sorted(capec_titles))
