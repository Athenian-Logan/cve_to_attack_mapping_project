import os
import pandas as pd
from SMET import map_text
import time

# THE PROGRAM IS CURRENTLY SET TO Enriched...

# Get program start time to track execution time at the end.
start_time = time.time()

# Suppress tokenizer warnings
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Load datasets
mitre_mappings = "scripts/SMET/datasets/mitre_cve_to_attack_mappings.csv"
mitre_mappings_data = pd.read_csv(mitre_mappings)

enriched = "scripts/SMET/datasets/enriched_dataset_from_mitre_cve_mappings.xlsx"
enriched_data = pd.read_excel(enriched)

# Initialize a mapping dictionary
mapping_dict = {}
for row in mitre_mappings_data.itertuples(index=False):
    mapping_dict.setdefault(row.ID, []).append(row.Mapping)

enriched_smet_mappings = {}

# Process enriched dataset
for row in enriched_data.itertuples(index=False):
    # Prepare enriched CVE data
    """if row.ID != "CVE-2018-20250": # Testing Purposes
        continue"""

    print(row.ID)
    print('*'*180)

    enriched_cve_data = []
    for attr in [row.Description, row._2, row._3, row._4]:
        if pd.notna(attr):  # Check if the value is not NaN
            enriched_cve_data.extend(str(attr).split('. '))  # Convert to string and split

    enriched_cve_data_combined = ' '.join(enriched_cve_data)
    # enriched_cve_data_combined = row.Description # For description only ofc

    # Map techniques and encode data
    enriched_possible_techniques = map_text(enriched_cve_data_combined, CVE=True)
    print(enriched_possible_techniques)

    print('*'*200)

    # Rank and filter techniques
    selected_techniques = [(tech, score) for tech, score in enriched_possible_techniques if score > 0.1]  # Threshold can be tuned
    # if len(selected_techniques) == 0:
    #    selected_techniques.extend(enriched_possible_techniques[0:3]) # Take the top three ranked, in absence of threshold being met.
    print(selected_techniques)

    # Sort techniques by score in descending order and select the top 3
    """filtered_selected_techniques = sorted(
        [(tech, score) for tech, score in enriched_possible_techniques if tech in selected_techniques],
        key=lambda x: x[1], 
        reverse=True
    )[:3]"""
    filtered_selected_techniques = selected_techniques # Just for now, want every technique over threshold...
    print("-" * 100)
    # Display results
    print("Possible Technique Ranks:")
    for technique, score in filtered_selected_techniques:
        print(f"{technique}: {score:.4f}")

    print("\nSelected Techniques:")
    print(filtered_selected_techniques)
    print("-" * 100)
    techniques = [tech for tech, score in filtered_selected_techniques]
    enriched_smet_mappings.setdefault(row.ID, techniques)

# Convert the dictionary into a DataFrame
processed_df = pd.DataFrame({
    "CVE_ID": enriched_smet_mappings.keys(),
    "filtered_selected_techniques": ['; '.join(map(str, techniques)) for techniques in enriched_smet_mappings.values()]
})

# Save the DataFrame to an Excel file
# output_path = "scripts/SMET/datasets/smet_description_only_mapped_cves.xlsx"
output_path = "scripts/SMET/datasets/smet_enriched_mapped_cves.xlsx"
processed_df.to_excel(output_path, index=False)

# Recorded --- 24.41 minutes --- of runtime over enriched dataset
# Recorded --- 12.27 minutes --- of runtime over description only dataset
print("--- %.2f minutes ---" % ((time.time() - start_time) / 60))
print(f"SMET Mappings saved to {output_path}")
