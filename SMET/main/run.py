from SMET import map_text
import pandas as pd

# Load the enriched dataset
enriched = "scripts/SMET/datasets/enriched_dataset.xlsx"
enriched_data = pd.read_excel(enriched)

# Check the column names
print("Columns:", list(enriched_data))

# Iterate through rows with the correct attribute names
for row in enriched_data.itertuples(index=False):
    enriched_cve_data = []

    print(f"ID: {row.ID}")
    if row.ID != "CVE-2020-15162":
        continue

    # Split the description into sentences and add to enriched_cve_data
    print(f"Description: {row.Description}")
    description_sentences = row.Description.split('. ')
    enriched_cve_data.extend(description_sentences)

    # Split the CVSS description into sentences and add to enriched_cve_data
    print(f"CVSS Description: {row._2}")
    cvss_sentences = row._2.split('. ')
    enriched_cve_data.extend(cvss_sentences)

    # Split the CWE description into sentences and add to enriched_cve_data
    print(f"CWE Description: {row._3}")
    cwe_sentences = row._3.split('. ')
    enriched_cve_data.extend(cwe_sentences)

    # Split the CPE description into sentences and add to enriched_cve_data
    print(f"CPE Description: {row._4}")
    cpe_sentences = row._4.split('. ')
    enriched_cve_data.extend(cpe_sentences)

    # Combine all sentences into a single string
    enriched_cve_data_combined = ' '.join(enriched_cve_data)
    print(f"Enriched CVE Data (as sentences): {enriched_cve_data_combined}")

    # Map the description only
    description_mapping = map_text(row.Description, CVE=True)
    print(description_mapping)
    
    print("-"*100)

    # Map the combined text
    enriched_mapping = map_text(enriched_cve_data_combined, CVE=True)
    print(enriched_mapping)
    break # Temporary

# For each CVE, map enriched data feed and then only description.
# From this, we will compare effectiveness of my approach and make graphs.
