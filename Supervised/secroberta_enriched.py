import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import RobertaTokenizer, RobertaForSequenceClassification
import ast

# Load the dataset
df = pd.read_csv("enriched_full_data.csv")

# Preprocess 'Techniques' column (convert from string representation of list to actual list)
df['Techniques'] = df['Techniques'].apply(lambda x: ast.literal_eval(x) if isinstance(x, str) else x)

tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")

class CVEDataset(Dataset):
    def __init__(self, dataframe, tokenizer, max_length=512):
        self.dataframe = dataframe
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.dataframe)

    def __getitem__(self, idx):
        row = self.dataframe.iloc[idx]
        text = f"{row['Description']} {row['CVSS Description']} {row['CWE Description']} {row['CPE Description']}"
        labels = torch.tensor(row['Techniques'], dtype=torch.long)

        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors="pt"
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": labels
        }

# Create dataset and dataloader
dataset = CVEDataset(df, tokenizer)
dataloader = DataLoader(dataset, batch_size=8, shuffle=True)

# Define the model (adjust output size based on number of techniques)
num_labels = max(max(df['Techniques'])) + 1  # Dynamic label size based on dataset
model = RobertaForSequenceClassification.from_pretrained("microsoft/codebert-base", num_labels=num_labels)

# Sample batch
for batch in dataloader:
    print(batch)
    break