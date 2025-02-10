import pandas as pd
import matplotlib.pyplot as plt

# Load Mitre CVE to ATT&CK mappings
mitre = "scripts/SMET/datasets/mitre_cve_to_attack_mappings.csv"
mitre_df = pd.read_csv(mitre)
print("Mitre Dataset:\n", mitre_df)

# Convert Mitre mappings into a dictionary
mitre_mappings_dict = mitre_df.groupby('ID')['Mapping'].apply(set).to_dict()

# Load SMET description-only mappings
smet_description_only = 'scripts/SMET/datasets/smet_description_only_mapped_cves.xlsx'
smet_description_only_df = pd.read_excel(smet_description_only)
print("\nSMET Description Only Dataset:\n", smet_description_only_df)

# Convert SMET description-only mappings into a dictionary
smet_description_only_dict = smet_description_only_df.set_index('CVE_ID')['filtered_selected_techniques'].dropna().apply(
    lambda x: set(x.split('; '))
).to_dict()

# Load SMET enriched mappings
smet_enriched = 'scripts/SMET/datasets/smet_enriched_mapped_cves.xlsx'
smet_enriched_df = pd.read_excel(smet_enriched)
print("\nSMET Enriched Dataset:\n", smet_enriched_df)

# Convert SMET enriched mappings into a dictionary
smet_enriched_dict = smet_enriched_df.set_index('CVE_ID')['filtered_selected_techniques'].dropna().apply(
    lambda x: set(x.split('; '))
).to_dict()

# Helper function to compare mappings

# Completely accurate mappings are 1:1,
# semi-accurate mappings wherein all mappings are present though the SMET mapping may include additional wrong mappings, 
# innaccurate mappings which do not include any correct mitre mappings. 

def compare_mappings(mitre_dict, smet_dict):
    completely_accurate = 0
    semi_accurate = 0
    inaccurate = 0

    for cve_id, mitre_mapping in mitre_dict.items():
        if cve_id in smet_dict:
            smet_mapping = smet_dict[cve_id]
            if mitre_mapping == smet_mapping:
                completely_accurate += 1
            elif mitre_mapping.issubset(smet_mapping):
                semi_accurate += 1
            else:
                inaccurate += 1
        else:
            inaccurate += 1

    return completely_accurate, semi_accurate, inaccurate

# Compare mappings for both SMET datasets
desc_only_results = compare_mappings(mitre_mappings_dict, smet_description_only_dict)
enriched_results = compare_mappings(mitre_mappings_dict, smet_enriched_dict)

# Print results
print("\nComparison Results:")
print("Description Only - Completely Accurate: {}, Semi-Accurate: {}, Inaccurate: {}".format(*desc_only_results))
print("Enriched - Completely Accurate: {}, Semi-Accurate: {}, Inaccurate: {}".format(*enriched_results))

# Create bar charts
labels = ['Completely Accurate', 'Semi-Accurate', 'Inaccurate']
desc_only_counts = list(desc_only_results)
enriched_counts = list(enriched_results)

x = range(len(labels))
width = 0.35  # Bar width

plt.figure(figsize=(10, 6))

# Plot bars
plt.bar(x, desc_only_counts, width, label='Description Only')
plt.bar([p + width for p in x], enriched_counts, width, label='Enriched')

# Add labels, legend, and title
plt.xlabel('Mapping Accuracy')
plt.ylabel('Number of CVEs')
plt.title('Comparison of SMET Mappings Accuracy Against Mitre Baseline')
plt.xticks([p + width / 2 for p in x], labels)
plt.legend()

# Show the bar chart
plt.tight_layout()
plt.show()
 