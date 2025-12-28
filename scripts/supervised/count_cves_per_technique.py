import pandas as pd
import ast

# Load datasets
df_cves = pd.read_csv("scripts/supervised/datasets/enriched_to_technique/enriched_full_data.csv")
df_techniques = pd.read_csv("scripts/supervised/datasets/techniques_numbered.csv")

# Create technique index-to-name mapping
tech_id_to_name = dict(zip(df_techniques['index'], df_techniques['name']))

# Prepare a dictionary to hold counts
technique_counts = {}

# Parse technique lists and count occurrences
for techniques_str in df_cves['Techniques']:
    try:
        # Convert string list like "[14, 116]" to actual list
        technique_ids = ast.literal_eval(techniques_str)
        for tech_id in technique_ids:
            tech_name = tech_id_to_name.get(tech_id, f"Unknown_{tech_id}")
            technique_counts[tech_name] = technique_counts.get(tech_name, 0) + 1
    except (ValueError, SyntaxError):
        continue  # Skip malformed entries

# Convert to DataFrame for sorting/saving
df_counts = pd.DataFrame.from_dict(technique_counts, orient='index', columns=['CVE Count'])
df_counts = df_counts.sort_values(by='CVE Count', ascending=False)

# Print results
#print(df_counts)
# Print in "Technique,Count" format for Google Sheets
for technique, row in df_counts.iterrows():
    print(f"{technique},{row['CVE Count']}")

