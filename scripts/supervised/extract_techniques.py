import pandas as pd

# Load CVE-to-Technique Mappings
mapping_file = "scripts/supervised/datasets/mitre_cve_to_attack_mappings.csv"
mappings_df = pd.read_csv(mapping_file)

# Extract unique mappings
unique_mappings = mappings_df['Mapping'].drop_duplicates().reset_index(drop=True)

# Create indexed mappings
techniques_numbered_df = pd.DataFrame({'index': range(len(unique_mappings)), 'name': unique_mappings})

# Save to CSV
output_file = "scripts/supervised/datasets/techniques_numbered.csv"
techniques_numbered_df.to_csv(output_file, index=False)

print(f"Processed dataset saved to {output_file}.")
