import pandas as pd
import json
from preprocess import *

# Load the original dataset with labels
original_file = "scripts/supervised/datasets/original/full_data.csv"
original_df = pd.read_csv(original_file)

# Load the NVD JSON data
nvd_json_file = "scripts/json_dumps/nvd_json_dump.json"
with open(nvd_json_file, "r") as json_file:
    nvd_cve_info = json.load(json_file)

# Restructure the NVD data into a dictionary keyed by CVE IDs
nvd_cve_info_dict = {entry['cve']['id']: entry['cve'] for entry in nvd_cve_info}

# Process each CVE ID from the original dataset
enriched_records = {}
for _, row in original_df.iterrows():
    cve_id = row['ID']
    cve_dict = nvd_cve_info_dict.get(cve_id, {})

    # Extract description
    description = next((desc['value'] for desc in cve_dict.get('descriptions', []) if desc['lang'] == 'en'), row['Text'])

    # Extract CVSS scores (v3 > v2)
    cvss_v2_vector = None
    cvss_v31_vector = None
    cvss_v30_vector = None
    if 'metrics' in cve_dict:
        cvss_v2_vector = next((metric['cvssData']['vectorString'] for metric in cve_dict['metrics'].get('cvssMetricV2', []) if 'cvssData' in metric), None)
        cvss_v31_vector = next((metric['cvssData']['vectorString'] for metric in cve_dict['metrics'].get('cvssMetricV31', []) if 'cvssData' in metric), None)
        cvss_v30_vector = next((metric['cvssData']['vectorString'] for metric in cve_dict['metrics'].get('cvssMetricV30', []) if 'cvssData' in metric), None)

    # Extract CWE IDs if available
    cwe_ids = None
    if 'weaknesses' in cve_dict:
        cwe_ids = [desc['value'] for weakness in cve_dict['weaknesses'] for desc in weakness.get('description', []) if 'value' in desc]
    preprocessed_cwe_ids = preprocess_cwe_ids(cwe_ids)

    # Extract CPE configurations
    cpe_info = []
    def extract_cpe(config):
        if 'cpeMatch' in config:
            for cpe in config['cpeMatch']:
                cpe_info.append(f"{cpe['criteria']} (Vulnerable: {cpe['vulnerable']})")
        if 'nodes' in config:
            for node in config['nodes']:
                extract_cpe(node)
    
    for config in cve_dict.get('configurations', []):
        extract_cpe(config)
    cpe_info = ', '.join(cpe_info) if cpe_info else None

    # Preprocess values
    preprocessed_cvss_v3 = preprocess_cvss_v3x(cvss_v31_vector) if cvss_v31_vector else preprocess_cvss_v3x(cvss_v30_vector)
    preprocessed_cvss_v2 = preprocess_cvss_v2(cvss_v2_vector) if cvss_v2_vector else None

    # Skip if any of CWE, CVSS, or CPE is missing
    if not (preprocessed_cwe_ids and (preprocessed_cvss_v3 or preprocessed_cvss_v2) and cpe_info):
        continue

    enriched_records[cve_id] = {
        'ID': cve_id,
        'Text': description,
        'CVSS': preprocessed_cvss_v3 if preprocessed_cvss_v3 else preprocessed_cvss_v2,
        'CWE': preprocessed_cwe_ids,
        'CPE': preprocess_cpe(cpe_info)
    }

# Convert enriched data to DataFrame
enriched_df = pd.DataFrame.from_dict(enriched_records, orient='index')

# Merge with the original dataset
final_df = original_df.merge(enriched_df, on=['ID', 'Text'], how='inner')

# Reorder columns
ordered_columns = ['ID', 'Text', 'CVSS', 'CWE', 'CPE'] + [col for col in original_df.columns if col not in ['ID', 'Text']]
final_df = final_df[ordered_columns]

# Save the final dataset
output_file = "scripts/supervised/datasets/enriched_simple_cwe_to_tactic/enriched_full_data.csv"
final_df.to_csv(output_file, index=False)

print(f"Data enrichment completed. File saved to {output_file}.")
