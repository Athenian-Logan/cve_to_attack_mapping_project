import csv
import json

### Extract Relevant CVEs from nvd_json_dump ###

# Specify the name of the input CSV file
specified_csv_name = "train_val_data"

# Read specified dataset (CSV) into a list of dictionaries
specified_dataset = []
with open(f"cve_to_attack_mapping_project/{specified_csv_name}.csv", "r", encoding="utf-8") as csv_file:
    reader = csv.DictReader(csv_file)
    specified_dataset = [row for row in reader]

# Read NVD JSON data into a list
nvd_cve_info = []
with open("cve_to_attack_mapping_project/scripts/json_dumps/nvd_json_dump.json", "r") as json_file:
    nvd_cve_info = json.load(json_file)

# Extract relevant CVEs
relevant_cves = []
for entry in specified_dataset:
    for nvd_cve in nvd_cve_info:
        if entry["ID"] == nvd_cve["cve"]["id"]:
            relevant_cves.append(nvd_cve)
            break  # Break to avoid redundant checks once matched

# Convert the output data to JSON format
output_json = json.dumps(relevant_cves, indent=4)

# Save the JSON to a file
output_file_name = f"cve_to_attack_mapping_project/scripts/json_dumps/{specified_csv_name}_relevant_nvd_dataset.json"
with open(output_file_name, "w") as json_file:
    json_file.write(output_json)

print(f"JSON data saved to {output_file_name}")
