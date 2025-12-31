import pandas as pd
import json
import os
from preprocess import *

def extract_cve_info_from_dict(cve_dict, cve_id):
    """Extract information from a CVE dictionary without needing the original row."""
    if not cve_dict:
        return None
    
    # Extract description
    description = next((desc['value'] for desc in cve_dict.get('descriptions', []) 
                       if desc['lang'] == 'en'), None)
    
    if not description:
        return None
    
    # Extract CVSS scores
    cvss_v2_vector = None
    cvss_v31_vector = None
    cvss_v30_vector = None
    
    if 'metrics' in cve_dict:
        cvss_v2_vector = next((metric['cvssData']['vectorString'] 
                              for metric in cve_dict['metrics'].get('cvssMetricV2', []) 
                              if 'cvssData' in metric), None)
        cvss_v31_vector = next((metric['cvssData']['vectorString'] 
                               for metric in cve_dict['metrics'].get('cvssMetricV31', []) 
                               if 'cvssData' in metric), None)
        cvss_v30_vector = next((metric['cvssData']['vectorString'] 
                               for metric in cve_dict['metrics'].get('cvssMetricV30', []) 
                               if 'cvssData' in metric), None)
    
    # Extract CWE IDs
    cwe_ids = None
    if 'weaknesses' in cve_dict:
        cwe_ids = [desc['value'] for weakness in cve_dict['weaknesses'] 
                  for desc in weakness.get('description', []) if 'value' in desc]
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
    
    # Select CVSS version
    selected_cvss_version = cvss_v31_vector if cvss_v31_vector else cvss_v30_vector
    
    # Check if all required fields are present
    if not (preprocessed_cwe_ids and (selected_cvss_version or cvss_v2_vector) and cpe_info):
        return None
    
    return {
        'ID': cve_id,
        'Text': description,
        'CVSS': selected_cvss_version if selected_cvss_version else cvss_v2_vector,
        'CWE': preprocessed_cwe_ids,
        'CPE': preprocess_cpe(cpe_info)
    }

def main():
    # Load the original dataset with labels
    original_file = "scripts/supervised/datasets/original/full_data.csv"
    original_df = pd.read_csv(original_file)
    
    # Create a set of CVE IDs we're looking for
    cve_ids_needed = set(original_df['ID'].tolist())
    print(f"Looking for {len(cve_ids_needed)} CVEs")
    
    # Directory containing NVD batch files
    batch_dir = "scripts/json_dumps/batches"
    batch_files = sorted([f for f in os.listdir(batch_dir) 
                         if f.startswith('nvd_batch_') and f.endswith('.json')])
    
    # Dictionary to store enriched records
    enriched_records = {}
    found_count = 0
    total_processed = 0
    
    # Process each batch file once
    for batch_file in batch_files:
        batch_path = os.path.join(batch_dir, batch_file)
        print(f"Processing batch: {batch_file} (found so far: {found_count})")
        
        with open(batch_path, "r") as json_file:
            batch_data = json.load(json_file)
        
        # Check each CVE in this batch
        for entry in batch_data:
            total_processed += 1
            cve_id = entry['cve']['id']
            
            # Only process if this CVE is in our needed list
            if cve_id in cve_ids_needed:
                cve_info = extract_cve_info_from_dict(entry['cve'], cve_id)
                if cve_info:
                    enriched_records[cve_id] = cve_info
                    found_count += 1
                    # Remove from set to avoid duplicate processing
                    cve_ids_needed.remove(cve_id)
        
        # Early exit if we've found all CVEs
        if not cve_ids_needed:
            print(f"Found all CVEs! Stopping early.")
            break
    
    print(f"\nProcessed {total_processed} CVEs from NVD")
    print(f"Found {found_count} matching CVEs with complete information")
    print(f"Missing {len(cve_ids_needed)} CVEs: {list(cve_ids_needed)[:10]}...")
    
    if enriched_records:
        # Convert enriched data to DataFrame
        enriched_df = pd.DataFrame.from_dict(enriched_records, orient='index')
        
        # Merge with the original dataset
        final_df = original_df.merge(enriched_df, on=['ID', 'Text'], how='inner')
        
        # Reorder columns
        original_columns = [col for col in original_df.columns if col not in ['ID', 'Text']]
        ordered_columns = ['ID', 'Text', 'CVSS', 'CWE', 'CPE'] + original_columns
        final_df = final_df[ordered_columns]
        
        # Save the final dataset
        output_file = "scripts/supervised/datasets/multi_modal/enriched_full_data.csv"
        final_df.to_csv(output_file, index=False)
        
        print(f"\nData enrichment completed. File saved to {output_file}.")
        print(f"Original rows: {len(original_df)}, Enriched rows: {len(final_df)}")
    else:
        print("No CVEs found in NVD data!")

if __name__ == "__main__":
    main()