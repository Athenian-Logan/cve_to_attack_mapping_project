import os
import pandas as pd
from SMET import map_text

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
    print(row.ID)
    enriched_cve_data = []
    for attr in [row.Description, row._2, row._3, row._4]:  # Adjust column access if needed
        if pd.notna(attr):  # Check if the value is not NaN
            enriched_cve_data.extend(str(attr).split('. '))  # Convert to string and split

    enriched_cve_data_combined = ' '.join(enriched_cve_data)

    # Map techniques and encode data
    enriched_possible_techniques = map_text(enriched_cve_data_combined, CVE=True)

    # Rank and filter techniques
    selected_techniques = [tech for tech, score in enriched_possible_techniques if score > 0.1]  # Threshold can be tuned
    
    print("-" * 100)
    # Display results
    print("Possible Technique Ranks:")
    for technique, score in enriched_possible_techniques:
        print(f"{technique}: {score:.4f}")

    print("\nSelected Techniques:")
    print(selected_techniques)
    print("-" * 100)
    enriched_smet_mappings.setdefault(row.ID, []).append(selected_techniques)

# Convert the dictionary into a DataFrame
processed_df = pd.DataFrame({
    "CVE_ID": enriched_smet_mappings.keys(),
    "Selected_Techniques": ['; '.join(map(str, techniques)) for techniques in enriched_smet_mappings.values()]
})

# Save the DataFrame to an Excel file
output_path = "scripts/SMET/datasets/smet_mapped_cves.xlsx"
processed_df.to_excel(output_path, index=False)

print(f"SMET Mappings saved to {output_path}")
