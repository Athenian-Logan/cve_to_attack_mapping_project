import main
import pandas as pd

# Load the enriched dataset
enriched = "scripts/SMET/datasets/enriched_dataset.xlsx"
enriched_data = pd.read_excel(enriched)

# Check the column names
print("Columns:", list(enriched_data))

# Iterate through rows with the correct attribute names
for row in enriched_data.itertuples(index=False):
    print(f"ID: {row.ID}")
    print(f"Description: {row.Description}")
    print(f"CVSS Description: {row._2}")
    print(f"CWE Description: {row._3}")
    print(f"CPE Description: {row._4}")

# For each CVE, map enriched data feed and then only description.
# From this, we will compare effectiveness of my approach and make graphs.
