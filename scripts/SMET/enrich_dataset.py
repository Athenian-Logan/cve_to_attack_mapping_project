import pandas as pd
import json
from preprocess import *

# Open and read initial SMET dataset.
data_file = "scripts/SMET/datasets/initial_dataset.xlsx"
data = pd.read_excel(data_file)
cve_data = data.to_dict(orient='records')

# Load NVD JSON data
nvd_cve_info = []
with open(f"scripts/json_dumps/nvd_json_dump.json", "r") as json_file:
    nvd_cve_info = json.load(json_file)

# Restructure the list into a dictionary keyed by CVE IDs
nvd_cve_info_dict = {entry['cve']['id']: entry['cve'] for entry in nvd_cve_info}

# Process each record in the CVE dataset
processed_data = []
for record in cve_data:
    id = record.get('ID')
    cve_dict = nvd_cve_info_dict.get(id)
    
    if not cve_dict:
        print(f"No data found for CVE ID: {id}")
        continue
    
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
    print(cwe_ids)
    
    # Extract CPE Info if available
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

    # Append the processed record
    processed_record = {
        'ID': id,
        'Description': record.get('Description'),
        'CVSS Description': preprocessed_cvss_v3 if preprocessed_cvss_v3 is not None else preprocessed_cvss_v2,
        'CWE Description': preprocessed_cwe_ids if len(preprocessed_cwe_ids)>0 else 'No weakness information known for CVE.',
        'CPE Description': preprocess_cpe(cpe_info)
    }
    processed_data.append(processed_record)


# Convert the processed data into a DataFrame and save it
processed_df = pd.DataFrame(processed_data)
processed_df.to_excel("scripts/SMET/datasets/enriched_dataset.xlsx", index=False)

print("Data processing completed. Processed dataset saved.")
