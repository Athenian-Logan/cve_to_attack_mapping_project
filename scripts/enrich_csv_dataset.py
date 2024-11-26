import json
import pandas as pd
import re
from cwe2.database import Database

# Initialize CWE database
db = Database()

# Load CSV dataset into a pandas DataFrame
specified_csv = "train_val_data"
input_csv_path = f"cve_to_attack_mapping_project/{specified_csv}.csv"
data = pd.read_csv(input_csv_path)

# Load NVD JSON data
nvd_cve_info = []
with open(f"cve_to_attack_mapping_project/scripts/json_dumps/{specified_csv}_relevant_nvd_dataset.json", "r") as json_file:
    nvd_cve_info = json.load(json_file)

# Functions for extracting CWE, CVSS, and CPE information
def format_cwe_info(weaknesses_info):
    formatted_weaknesses = []
    for weakness in weaknesses_info:
        for cwe in weakness.get("description", []):
            match = re.search(r"CWE-(\d+)", cwe["value"])
            if match:
                cwe_lookup = db.get(match.group(1))
                if cwe_lookup:
                    cwe_info = f"{cwe_lookup.cwe_id}: {cwe_lookup.name} - {cwe_lookup.description}"
                    if cwe_info not in formatted_weaknesses:
                        formatted_weaknesses.append(cwe_info)
    return "; ".join(formatted_weaknesses)  # Join with semicolons for CSV readability

def format_cvss_info(metrics_info):
    formatted_metrics = []
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric = metrics_info.get(version, [{}])[0]
        if metric:
            cvss_data = metric.get('cvssData', {})
            # Extract all vector fields
            vectors = {k: v for k, v in cvss_data.items() if k != "baseScore"}  # Exclude baseScore if desired
            vector_string = ", ".join(f"{k}: {v}" for k, v in vectors.items())
            
            formatted_metrics.append(
                f"Version: {version[-3:]}, Score: {cvss_data.get('baseScore', 'N/A')}, Vectors: ({vector_string})"
            )
    return "; ".join(formatted_metrics)

def format_configs(configurations_info):
    pattern = re.compile(r"^cpe:2\.3:([aoh]):(\w+):([^:]+):")
    component_types = {"a": "Application", "o": "Operating System", "h": "Hardware"}
    formatted_cpes = []
    for config in configurations_info:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", "false") == "false":
                    continue
                cpe_string = cpe_match["criteria"]
                cpe_matches = pattern.match(cpe_string)
                if cpe_matches:
                    cpe_info = f"{component_types.get(cpe_matches.group(1), 'Unknown')} - Vendor: {cpe_matches.group(2)}, Product: {cpe_matches.group(3)}"
                    formatted_cpes.append(cpe_info)
    return "; ".join(formatted_cpes)

# Enrich the DataFrame with NVD data
cwe_info_list = []
cvss_info_list = []
cpe_info_list = []

for index, row in data.iterrows():
    cve_id = row["ID"]
    matched_nvd_entry = next((nvd for nvd in nvd_cve_info if nvd["cve"]["id"] == cve_id), None)
    if matched_nvd_entry:
        weaknesses_info = matched_nvd_entry["cve"].get("weaknesses", [])
        metrics_info = matched_nvd_entry["cve"].get("metrics", {})
        configurations_info = matched_nvd_entry["cve"].get("configurations", [])
        
        cwe_info_list.append(format_cwe_info(weaknesses_info))
        cvss_info_list.append(format_cvss_info(metrics_info))
        cpe_info_list.append(format_configs(configurations_info))
    else:
        cwe_info_list.append("")
        cvss_info_list.append("")
        cpe_info_list.append("")

# Add the extracted data to new columns
data["CWE Info"] = cwe_info_list
data["CVSS Info"] = cvss_info_list
data["CPE Info"] = cpe_info_list

# Reorder columns to place new data immediately after "Text"
existing_columns = list(data.columns)
if "Text" in existing_columns:
    text_index = existing_columns.index("Text")
    reordered_columns = (
        existing_columns[:text_index + 1]  # Columns up to and including "Text"
        + ["CWE Info", "CVSS Info", "CPE Info"]  # New columns
        + existing_columns[text_index + 1:]  # Remaining columns after "Text"
    )
    data = data[reordered_columns]

# Save the enriched DataFrame back to a CSV file
output_csv_path = f"cve_to_attack_mapping_project/scripts/enriched_datasets/{specified_csv}_enriched_test_data.csv"
data.to_csv(output_csv_path, index=False)

print(f"Enriched CSV saved to {output_csv_path}")
