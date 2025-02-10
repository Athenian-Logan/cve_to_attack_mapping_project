import pandas as pd
import json
from preprocess import *

# Load the CVE IDs from the mitre_cve_to_attack_mappings.csv file
mapping_file = "scripts/supervised/datasets/mitre_cve_to_attack_mappings.csv"
mappings = pd.read_csv(mapping_file)

# Convert the list of IDs to a set to remove duplicates
mapping_ids = set(mappings['ID'].tolist())
mapped_techniques = mappings.groupby(['ID']).agg({'Mapping': ', '.join}).reset_index()

# Load the NVD JSON data
nvd_json_file = "scripts/json_dumps/nvd_json_dump.json"
with open(nvd_json_file, "r") as json_file:
    nvd_cve_info = json.load(json_file)

# Restructure the NVD data into a dictionary keyed by CVE IDs
nvd_cve_info_dict = {entry['cve']['id']: entry['cve'] for entry in nvd_cve_info}

# Process each unique CVE ID from the mapping file
processed_data = []
for cve_id in mapping_ids:  # Iterate over unique IDs
    cve_dict = nvd_cve_info_dict.get(cve_id)

    if not cve_dict:
        print(f"No data found for CVE ID: {cve_id}")
        continue

    # Extract the English description
    description = next((desc['value'] for desc in cve_dict.get('descriptions', []) if desc['lang'] == 'en'), "No description available")

    # Extract CVSS v2 and CVSS v3 vector strings if available
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

    cpe_info = None
    if 'configurations' in cve_dict:
        cpe_info = []
        def extract_cpe(config):
            if 'cpeMatch' in config:
                for cpe in config['cpeMatch']:
                    cpe_info.append({
                        'criteria': cpe['criteria'],
                        'vulnerable': cpe['vulnerable']
                    })
            if 'nodes' in config:
                for node in config['nodes']:
                    extract_cpe(node)

        for config in cve_dict['configurations']:
            extract_cpe(config)
        
        # Join CPE entries into a readable string format
        cpe_info = ', '.join(f"{cpe['criteria']} (Vulnerable: {cpe['vulnerable']})" for cpe in cpe_info) if cpe_info else None

    preprocessed_cvss_v3 = preprocess_cvss_v3x(cvss_v31_vector) if cvss_v31_vector is not None else preprocess_cvss_v3x(cvss_v30_vector)
    preprocessed_cvss_v2 = preprocess_cvss_v2(cvss_v2_vector) if cvss_v2_vector is not None else None

    preprocessed_cwe_ids = preprocess_cwe_ids(cwe_ids)

    techniques_to_vector_mappings = pd.read_csv("scripts/supervised/datasets/techniques_numbered.csv")

    # Fetch the corresponding techniques mapping
    techniques = mapped_techniques.loc[mapped_techniques['ID'] == cve_id, 'Mapping'].values
    techniques = techniques[0].split(', ') if len(techniques) > 0 and isinstance(techniques[0], str) else []

    # Convert technique name-to-index mapping for efficient lookup
    technique_name_to_index = techniques_to_vector_mappings.set_index('name')['index'].to_dict()
    vectorised_techniques = [technique_name_to_index.get(tech, None) for tech in techniques]
    vectorised_techniques = [idx for idx in vectorised_techniques if idx is not None]  # Remove None values

    # Debugging
    print("*" * 100)
    print(f"Techniques for {cve_id}: {techniques}")
    print(f"Technique Index Mapping: {vectorised_techniques}")
    print(f"Available technique names: {list(technique_name_to_index.keys())[:10]}")  # Show first 10 names
    print("*" * 100)

    # Append the processed record
    processed_record = {
        'ID': cve_id,
        'Description': description,
        'CVSS Description': preprocessed_cvss_v3 if preprocessed_cvss_v3 is not None else preprocessed_cvss_v2,
        'CWE Description': preprocessed_cwe_ids if len(preprocessed_cwe_ids) > 0 else 'No weakness information known for CVE.',
        'CPE Description': preprocess_cpe(cpe_info),
        'Techniques': vectorised_techniques
    }
    processed_data.append(processed_record)

# Convert the processed data into a DataFrame and save it as an Excel file
processed_df = pd.DataFrame(processed_data)
output_file = "scripts/supervised/datasets/enriched_to_technique/enriched_full_data.csv"
processed_df.to_csv(output_file, index=False)

print(f"Data processing completed. Processed dataset saved to {output_file}.")
