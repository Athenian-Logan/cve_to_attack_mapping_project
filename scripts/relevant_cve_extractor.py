import json

### Extract Relevant CVEs from nvd_json_dump. ###

# Read Initial Dataset and Load to JSON.
initial_dataset = []
with open("scripts\\json_dumps\\initial_dataset.json", "r") as json_file:
    initial_dataset = json.load(json_file)

# Read NVD JSON and Enrich Initial Dataset.
nvd_cve_info = []
with open("scripts\\json_dumps\\nvd_json_dump.json", "r") as json_file:
    nvd_cve_info = json.load(json_file)

# Iterate initial Dataset. For each entry, check NVD JSON, then extract nvd json.
relevant_cves = []
for entry in initial_dataset:
    for nvd_cve in nvd_cve_info:
        if entry["ID"] == nvd_cve["cve"]["id"]:
            relevant_cves.append(nvd_cve)
            break

# Convert the output data to JSON format
output_json = json.dumps(relevant_cves, indent=4)

# Save the JSON to a file
with open("scripts\\json_dumps\\relevant_nvd_dataset.json", "w") as json_file:
    json_file.write(output_json)

print("JSON data saved to initial_dataset.json")