import json
import csv

# Load the JSON data
json_file = "scripts/json_dumps/cve-10.21.2021_attack-9.0-enterprise_json.json"  
csv_file = "scripts/SMET/datasets/mitre_cve_to_attack_mappings.csv"  # Output CSV file path

with open(json_file, 'r') as file:
    data = json.load(file)

# Extract mapping objects
mapping_objects = data.get("mapping_objects", [])

# Prepare data for CSV
csv_data = []
for obj in mapping_objects:
    capability_id = obj.get("capability_id", "")
    attack_object_name = obj.get("attack_object_name", "")
    if capability_id and attack_object_name:
        csv_data.append({"ID": capability_id, "Mapping": attack_object_name})

# Write to CSV
with open(csv_file, 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=["ID", "Mapping"])
    writer.writeheader()
    writer.writerows(csv_data)

print(f"CSV file '{csv_file}' has been created with {len(csv_data)} entries.")
