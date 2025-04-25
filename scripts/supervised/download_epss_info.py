import pandas as pd
import requests
import time

# File paths
input_file = "scripts/supervised/datasets/enriched_with_capec_tactic/enriched_full_data.csv"
output_file = "scripts/supervised/datasets/enriched_with_capec_tactic/enriched_full_data.csv"

# Load the CSV file into a DataFrame
df = pd.read_csv(input_file, encoding="utf-8")

# Extract CVE IDs from the first column
cve_list = df.iloc[:, 0].tolist()

# Dictionary to store EPSS scores
epss_scores = {}

# Fetch EPSS scores in chunks
chunk_size = 50
for i in range(0, len(cve_list), chunk_size):
    chunk = cve_list[i:i + chunk_size]
    url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
    
    try:
        req = requests.get(url)
        print(f"Status Code: {req.status_code}, Chunk {i//chunk_size + 1}")

        if req.status_code == 200 and req.text.strip():
            data = req.json()
            if "data" in data:
                # If 'data' is a list, iterate over each item
                if isinstance(data["data"], list):
                    for item in data["data"]:
                        cve_id = item.get("cve")
                        epss_scores[cve_id] = item.get("epss", 0.0)
                else:
                    # If 'data' is a dict, iterate over its items (fallback)
                    for cve_id, info in data["data"].items():
                        epss_scores[cve_id] = info.get("epss", 0.0)
        else:
            print(f"Skipping chunk due to API error: {req.text}")
    
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    
    time.sleep(1)  # To avoid hitting rate limits

# Insert the EPSS column somewhere before the label columns.
# This inserts it as the third column (index 2).
df.insert(2, "EPSS", df.iloc[:, 0].map(epss_scores))

# Save the updated DataFrame
df.to_csv(output_file, index=False, encoding="utf-8")
print(f"Updated dataset saved to: {output_file}")
