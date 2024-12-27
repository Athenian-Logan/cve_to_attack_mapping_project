import re

def preprocess_cvss_v2(cvss):
    pattern = r'AV:([LAN])\/AC:([HML])\/Au:([MSN])\/C:([NPC])\/I:([NPC])\/A:([NPC])'
    vectors = re.match(pattern, cvss)

    if vectors is None:
        return None
    
    # Mappings for each Vector Value
    attack_vector_map = {'L': 'Local', 'A': 'Adjacent Network', 'N': 'Network'}
    complexity_map = {'H': 'High', 'M': 'Medium', 'L': 'Low'}
    auth_map = {'S': 'Single', 'M': 'Multiple', 'N': 'None'}
    impact_map = {'N': 'no', 'P': 'partial', 'C': 'complete'}
    
    # Retrieve Mapping for Matched Value
    attack_vector = attack_vector_map.get(vectors.group(1), "Unknown")
    access_complexity = complexity_map.get(vectors.group(2), "Unknown")
    authentication = auth_map.get(vectors.group(3), "Unknown")
    confidentiality_impact = impact_map.get(vectors.group(4), "Unknown")
    integrity_impact = impact_map.get(vectors.group(5), "Unknown")
    availability_impact = impact_map.get(vectors.group(6), "Unknown")

    # Construct Natural Lanugage CVSS V2 Description
    return f"""
            The CVE is exploited via the {attack_vector} Attack Vector. 
            The Attack Complexity is {access_complexity}.
            The attacker requires {authentication} Authentication.
            There is {confidentiality_impact} impact on Confidentiality.
            There is {integrity_impact} impact on Integrity.
            There is {availability_impact} impact on Availability.
            """

def preprocess_cvss_v3x(cvss):
    pass

def preprocess_cpe(cpe):
    pass