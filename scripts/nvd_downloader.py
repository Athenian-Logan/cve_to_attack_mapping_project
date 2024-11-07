import json
import requests
import time
import logging

logging.basicConfig(level=logging.DEBUG)

# Load Initial Dataset as JSON.
logging.info("Reading Initial Dataset to JSON.")
with open("scripts\\json_dumps\\initial_dataset.json", "r") as file:
    dataset = json.load(file)

# Iterate Initial Dataset and extract all CVE IDs.
logging.info("Extracting CVE IDs from Initial Dataset JSON.")
cve_ids = []

for mapping in dataset:
    cve_ids.append(mapping["ID"].replace("_", "-"))

# Request each CVE from NVD.
logging.info("Beginning NVD Downloader...")
api_keys = ["5f3da5bb-16ed-46b9-a087-ec18e47ec5cb",
            "7261ae13-e9ca-4741-b843-7160cc301a5d",
            "13e2c275-97f5-4e7a-a800-5f3fdcc0d785",
            "af7a431d-ec71-4f30-868c-d661649d65f4",
            "6061ab83-e57d-4d83-8594-7fe35463afb9"]
key_iterator = 0
nvd_cve_info = []
cve_id = 0

while True:
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_ids[cve_id]}"
    headers = {
    "apiKey": api_keys[key_iterator]
    }

    logging.info(f"Requesting NVD JSON for {cve_ids[cve_id]}")
    response = requests.get(nvd_api_url, headers=headers)

    if response.status_code != 200:
        logging.error(f"Error: {response.status_code}\n{response.text}")

        # wait 5 seconds...
        logging.info("Waiting 5 Seconds...")
        time.sleep(5)

        # use new api key...
        logging.info("Iterating API Key...")
        key_iterator = key_iterator + 1 if key_iterator + 1 < len(api_keys) else 0
        logging.info(f"Using API Key: {api_keys[key_iterator]}")

    else:
       logging.info("Successful Request.")
       response_json = json.loads(response.text)
       nvd_cve_info.append(response_json["vulnerabilities"][0]) # Should always just be one vuln response...
       cve_id+=1
       if cve_id >= len(cve_ids):
           break

# Save nvd cve info to json dump.
logging.info("Saving NVD JSON Info to JSON Dump.")
with open("scripts\\json_dumps\\nvd_cve_info.json", "w") as json_file:
    json_file.write(nvd_cve_info)