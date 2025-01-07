import pandas as pd

# Look at mitre cve to att&ck mappings
mitre = "scripts/SMET/datasets/mitre_cve_to_attack_mappings.csv"
mitre_df = pd.read_csv(mitre)
print(mitre_df)

# Convert the list of mappings to a set to remove duplicates
mitre_mappings_list_no_dupes = set((mitre_df['ID'], mitre_df['Mappings']).tolist())
print(mitre_mappings_list_no_dupes)

# Look at SMET Description only mappings
smet_description_only = 'file_path.xlsx'
smet_description_only_df = pd.read_excel(smet_description_only)
print(smet_description_only_df)

# Look at SMET Enriched mappings
smet_enriched = 'file_path.xlsx'
smet_enriched_df = pd.read_excel(mitre)
print(smet_enriched_df)

# Compare the accuracy of both SMET mappings to Mitre CVE to Att&ck Mappings.

# Make a couple of graphs n that stuff.