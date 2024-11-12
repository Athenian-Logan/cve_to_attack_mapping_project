### Enrich Initial Dataset Using Relevant NVD Dataset, Inserting CWE, CVSS and CPE Information. ###

import json
from cwe2.database import Database
import re

# Initialise cwe database, for id lookup.
db = Database()

# Read Initial Dataset and Load to JSON.
initial_dataset = []    
with open("scripts\\json_dumps\\initial_dataset.json", "r") as json_file:
    initial_dataset = json.load(json_file)

# Read Relevant NVD JSON and Load to JSON.
nvd_cve_info = []
with open("scripts\\json_dumps\\nvd_json_dump.json", "r") as json_file:
    nvd_cve_info = json.load(json_file)

# Add Format Functions for Extracted Info.

# Include CWE ID, Name and Description. Avoiding duplication.
def format_cwe_info(weaknesses_info):
    formatted_weaknesses = []

    for weakness in weaknesses_info:
        for cwe in weakness["description"]:
            match = re.search(r'CWE-(\d+)', cwe["value"])
            if match:
                cwe_lookup = db.get(match.group(1))
                cwe_info = {
                    "CWE ID": cwe_lookup.cwe_id,
                    "CWE Name": cwe_lookup.name,
                    "CWE Description": cwe_lookup.description
                    }
                
                if cwe_info in formatted_weaknesses:
                    continue
                else:
                    formatted_weaknesses.append(cwe_info)

    return formatted_weaknesses

# Only take primary cvss source, for each version. 
def format_cvss_info(metrics_info):
    formatted_metrics = []

    formatted_metrics.append(metrics_info.get("cvssMetricV31", [None])[0])
    formatted_metrics.append(metrics_info.get("cvssMetricV30", [None])[0])
    formatted_metrics.append(metrics_info.get("cvssMetricV2", [None])[0])

    return formatted_metrics

# cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
def format_configs(configurations_info):
    pattern = re.compile(r"^cpe:2\.3:([aoh]):(\w+):([^:]+):")
    component_types = {
        "a": "Application",
        "o": "Operating System",
        "h": "Hardware"
    }

    formatted_cpes = []
    for config in configurations_info:
        for node in config["nodes"]:
            for cpe_match in node["cpeMatch"]:
                if cpe_match["vulnerable"] == "false":
                    continue

                cpe_string = cpe_match["criteria"]
                cpe_matches = pattern.match(cpe_string)
                
                if cpe_matches:
                    cpe_info = {
                        "Component Type": component_types.get(cpe_matches.group(1), "Unknown"),
                        "Vendor": cpe_matches.group(2),
                        "Product": cpe_matches.group(3)
                    }
                    formatted_cpes.append(cpe_info)

    return formatted_cpes


# Iterate nvd_cve_info. For each entry, extract CWE, CVSS and CPE. Format this info and insert into initial dataset.
for entry in initial_dataset:
    for nvd_cve in nvd_cve_info:
        if entry["ID"] == nvd_cve["cve"]["id"]:
            weaknesses_info = nvd_cve["cve"].get("weaknesses", [])
            entry["Weaknesses"] = format_cwe_info(weaknesses_info)
            
            metrics_info = nvd_cve["cve"].get("metrics", {})
            entry["Metrics"] = format_cvss_info(metrics_info)
            
            configurations_info = nvd_cve["cve"].get("configurations", [])
            entry["Platforms"] = format_configs(configurations_info)
            
            break

# Convert the initial_dataset to JSON format
output_json = json.dumps(initial_dataset, indent=4)

# Save the JSON to a file
with open("scripts\\json_dumps\\enriched_dataset.json", "w") as json_file:
    json_file.write(output_json)

print("JSON data saved to initial_dataset.json")