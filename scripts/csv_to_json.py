import pandas as pd
import json

# TODO: Add so that tactic names are separate from technique, and techniques are nested in tactics...

# Load the CSV data
df = pd.read_csv("C:\\Users\\johnr\\Downloads\\CVE2ATT&CK_dataset.csv")

# Initialize a list to store the extracted data
output_data = []

# Iterate through each row in the dataframe
for _, row in df.iterrows():
    # Extract ID and Description
    entry = {
        "ID": row["ID"],
        "Description": row["Description"],
        "Techniques": []
    }
    
    # Iterate through each column (except 'ID' and 'Description')
    for column in df.columns[2:]:
        # Check if the value is 1, indicating active technique
        if row[column] == 1:
            entry["Techniques"].append(column)
    
    # Append entry to output data if there are any techniques with value 1
    if entry["Techniques"]:
        output_data.append(entry)

# Convert the output data to JSON format
output_json = json.dumps(output_data, indent=4)

# Save the JSON to a file
with open("scripts\\json_dumps\\initial_dataset.json", "w") as json_file:
    json_file.write(output_json)

print("JSON data saved to output.json")
