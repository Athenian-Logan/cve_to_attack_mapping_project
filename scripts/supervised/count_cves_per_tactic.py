import pandas as pd

# Load your dataset
df = pd.read_csv("scripts/supervised/datasets/original/full_data.csv")

# List of MITRE ATT&CK tactic columns in your dataset
tactic_columns = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

# Sum each column to count how many CVEs are tagged with that tactic
tactic_counts = df[tactic_columns].sum().astype(int)

# Display results
print("ATT&CK Tactic CVE Counts:")
for tactic, count in tactic_counts.items():
    print(f"{tactic:25s}: {count:,}")
