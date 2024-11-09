import json
import requests
import time
import logging

logging.basicConfig(level=logging.DEBUG)

# Request NVD CVE Info.
logging.info("Beginning NVD Downloader...")
api_keys = ["5f3da5bb-16ed-46b9-a087-ec18e47ec5cb",
            "7261ae13-e9ca-4741-b843-7160cc301a5d",
            "13e2c275-97f5-4e7a-a800-5f3fdcc0d785",
            "af7a431d-ec71-4f30-868c-d661649d65f4",
            "6061ab83-e57d-4d83-8594-7fe35463afb9"]
key_iterator = 0
nvd_cve_info = []
start_index = 0
results_per_page = 2000

while True:
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={results_per_page}&startIndex={start_index}"
    headers = {
    "apiKey": api_keys[key_iterator]
    }

    logging.info(f"Requesting NVD JSON for Start Index: {start_index}")
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
        continue

    logging.info("Successful Request.")
    response_json = json.loads(response.text)
    if len(response_json["vulnerabilities"]) > 0:
        nvd_cve_info.extend(response_json["vulnerabilities"])
        start_index+=results_per_page
    else:
        break

# Convert the NVD data to JSON format
output_json = json.dumps(nvd_cve_info, indent=4)

# Save nvd cve info to json dump.
logging.info("Saving NVD JSON Info to JSON Dump.")
with open("scripts\\json_dumps\\nvd_json_dump.json", "w") as json_file:
    json_file.write(output_json)