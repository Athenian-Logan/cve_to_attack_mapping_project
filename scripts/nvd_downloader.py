import json
import requests

# Load Initial Dataset as JSON.
with open("scripts\\json_dumps\\initial_dataset.json", "r") as file:
    dataset = json.load(file)

# Iterate Initial Dataset and extract all CVE IDs.
cve_ids = []
for mapping in dataset:
    cve_ids.append(mapping["ID"].replace("_", "-"))

# Request each CVE from NVD and save to NVD JSON dump.
headers = {
    "apiKey": "5f3da5bb-16ed-46b9-a087-ec18e47ec5cb"
}
nvd_cve_info = []
for cve_id in cve_ids: # TODO: Add some error handling and waits...
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get('https://api.example.com/data', headers=headers)
    nvd_cve_info.append(response.json)

# Iterate each NVD JSON Dump, extract CWE, CPE and CVSS information and insert into Enriched Dataset.
