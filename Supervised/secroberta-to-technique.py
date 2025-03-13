import pandas as pd
import numpy as np
import pickle
import matplotlib.pyplot as plt
import seaborn as sns
import re
import copy
from tqdm import tqdm
import gc
import ast

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import optim
from torch.utils.data import Dataset, DataLoader

from sklearn.model_selection import train_test_split

from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    classification_report
)

from transformers import (
    AutoTokenizer,
    AutoModel,
    get_linear_schedule_with_warmup
)

import nltk
import re
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer, WordNetLemmatizer
from nltk.tokenize import word_tokenize

from transformers import BertTokenizer, BertForMaskedLM
from transformers import AutoTokenizer, AutoModelForMaskedLM

from sklearn.metrics import (
    recall_score,
    precision_score
)

from sklearn.metrics import multilabel_confusion_matrix

################################################################
# Global variables to store best metrics
BEST_F1 = 0
BEST_TRUE = []
BEST_PREDICTED = []

################################################################
# Preprocessing functions

def clean_abstract(text):
    # Replace version numbers with the word "version"
    version_pattern = r"\d+(\.\d+)+"
    updated_text = re.sub(version_pattern, "version", text)

    # Replace CVE references
    cve_pattern = r'CVE-\d{1,5}-\d{1,5}'
    updated_text = re.sub(cve_pattern, "CVE", updated_text)

    return updated_text

"""
def clean_cpe(text):
    # regex to match vendor product and component
    product_pattern = r"The CVE affects (?P<vendor>[a-zA-Z0-9_ \-\\\/]+) (?P<product>[a-zA-Z0-9_ \-\\\/]+) (?P<component>Operating System|Application|Hardware)\."

    match = re.search(product_pattern, text)
    if match:
        return f"The CVE affects {match.group('vendor')} Product {match.group('component')}."
        # return f"The CVE affects {match.group('component')}."

    return text  # Return original text if no match
"""

def clean_cpe(text):
    """Replace general product names with 'Product' while preserving OS names."""

    # OS names to preserve
    os_keywords = ["Windows", "MacOS", "Linux", "Mac_os_x", "Linux_kernel"]

    # Regex to match vendor, product, and component
    product_pattern = (
        r"The CVE affects (?P<vendor>[a-zA-Z0-9_ \-\\\/]+) "
        r"(?P<product>[a-zA-Z0-9_ \-\\\/]+) "
        r"(?P<component>Operating System|Application|Hardware)\."
    )

    match = re.search(product_pattern, text)
    if match:
        vendor, product, component = match.group("vendor"), match.group("product"), match.group("component")
        
        # Preserve known OS names
        if any(os_name.lower() in product.lower() for os_name in os_keywords):
            return f"The CVE affects {vendor} {product} {component}."
        
        # Generalise other product names
        return f"The CVE affects {vendor} Product {component}."

    return text  # Return original text if no match

def get_descriptions(df):
    descriptions = df['Description'].apply(clean_abstract)
    return descriptions.tolist()

def get_cvss(df):
    return df['CVSS Description'].tolist()

def get_cwe(df):
    return df['CWE Description'].tolist()

def get_cpe(df):
    cpe = df['CPE Description'].apply(clean_cpe)
    # print(cpe.tolist())
    return cpe.tolist()
    # return df['CPE Description'].tolist()

def get_labels(df):
    """
    Convert the 'Techniques' column (a string like "[14, 116]") into a multi–hot vector.
    Assumes that valid labels are 0-indexed (i.e. in the range 0 to Config().NUM_LABELS - 1).
    """
    labels = []
    for l in df['Techniques'].values:
        # Convert the string representation to a list if needed
        if isinstance(l, str):
            try:
                l = ast.literal_eval(l)
            except Exception as e:
                print("Error converting label:", l, e)
                l = []
        one_hot = np.zeros(Config().NUM_LABELS, dtype=np.float32)
        for idx in l:
            if 0 <= idx < Config().NUM_LABELS:
                one_hot[idx] = 1
            else:
                print(f"Warning: label {idx} is out of expected range")
        labels.append(one_hot)
    return np.array(labels)

def get_ids(df):
    return df['ID'].tolist()

################################################################
# Config

class Config:
    def __init__(self):
        super(Config, self).__init__()
        self.SEED = 42
        self.MODEL_PATH = 'jackaduma/SecRoBERTa'
        self.NUM_LABELS = 120  # valid indices are 0 to 119

        self.TOKENIZER = AutoTokenizer.from_pretrained(self.MODEL_PATH)
        self.MAX_LENGTH = 320
        self.BATCH_SIZE = 16

        self.DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.FULL_FINETUNING = True
        self.LR = 3e-5
        self.OPTIMIZER = 'AdamW'
        self.CRITERION = 'BCEWithLogitsLoss'
        self.N_VALIDATE_DUR_TRAIN = 3
        self.N_WARMUP = 0
        self.SAVE_BEST_ONLY = True
        self.EPOCHS = 5

################################################################
# Dataset & Dataloader

class TransformerDataset(Dataset):
    def __init__(self, df, indices, set_type=None):
        super(TransformerDataset, self).__init__()

        df = df.iloc[indices]
        self.descriptions = get_descriptions(df)
        self.cvss = get_cvss(df)
        self.cwe = get_cwe(df)
        self.cpe = get_cpe(df)
        self.set_type = set_type
        if self.set_type != 'test':
            self.labels = get_labels(df)

        self.tokenizer = Config().TOKENIZER
        self.max_length = Config().MAX_LENGTH

    def __len__(self):
        return len(self.descriptions)

    def __getitem__(self, index):
        # Concatenate all text fields into one string
        text = " ".join([
            str(self.descriptions[index]),
            str(self.cvss[index]),
            str(self.cwe[index]),
            str(self.cpe[index])
        ])
        """text = " ".join([
            str(self.descriptions[index]),
            str(self.cvss[index]),
            str(self.cwe[index]),
            str(None)
        ]) # Temporary, find F1 score on all except CPE only."""
        tokenized = self.tokenizer.encode_plus(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_attention_mask=True,
            return_token_type_ids=False,
            return_tensors='pt'
        )

        input_ids = tokenized['input_ids'].squeeze()
        attention_mask = tokenized['attention_mask'].squeeze()

        if self.set_type != 'test':
            # Convert the label (which is a numpy array) to a tensor.
            labels = torch.Tensor(self.labels[index])
            # Debug: Print shape if needed
            # print(f"Label Shape: {labels.shape}")
            return {
                'input_ids': input_ids.long(),
                'attention_mask': attention_mask.long(),
                'labels': labels,
            }

        return {
            'input_ids': input_ids.long(),
            'attention_mask': attention_mask.long(),
        }

################################################################
# Model

class Model(nn.Module):
    def __init__(self):
        super(Model, self).__init__()
        self.transformer_model = AutoModel.from_pretrained(Config().MODEL_PATH)
        self.dropout = nn.Dropout(0.3)
        self.output = nn.Linear(768, Config().NUM_LABELS)

    def forward(self, input_ids, attention_mask=None, token_type_ids=None):
        # Some transformer models do not return token_type_ids – adjust as needed.
        _, o2 = self.transformer_model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            return_dict=False
        )
        x = self.dropout(o2)
        out = self.output(x)
        return out

################################################################
# Train and test functions

def compute_metrics(predicted_y, true_y, metric_function, columns, limit):
    results = pd.DataFrame(columns=columns)
    # For accuracy_score we call without average parameter.
    if metric_function == accuracy_score:
        results.loc[len(results)] = metric_function(true_y, predicted_y)
    else:
        results.loc[len(results)] = metric_function(true_y, predicted_y, average=None)

    sorted_results = results.sort_values(by=0, axis=1, ascending=False)
    for col in sorted_results.columns[:limit]:
        print(f"{col}: {sorted_results[col].values[0]}")
    return sorted_results.iloc[:, :limit]

def print_F1_based_on_distribution(y_true, y_pred, Y, columns):
    fig, ax = plt.subplots()
    results = pd.DataFrame(columns=columns)
    results.loc[len(results)] = f1_score(y_true, y_pred, average=None)
    Y_count = Y.apply(np.sum, axis=0)
    Y_count_sorted = Y_count.sort_values(ascending=False)
    ax.bar(Y_count_sorted.index, Y_count_sorted.values)
    ax.set_xlabel("Technique")
    ax.set_ylabel("Number of CVEs")
    plt.xticks(rotation=90)
    ax2 = ax.twinx()
    ax2.plot(Y_count_sorted.index, results[Y_count_sorted.index].iloc[0], color='red')
    ax2.set_ylabel("F1 Score")
    plt.show()

def val(model, val_dataloader, criterion, is_final_test=False):
    global BEST_F1, BEST_TRUE, BEST_PREDICTED, device

    val_loss = 0
    true, pred = [], []
    model.eval()

    for step, batch in enumerate(val_dataloader):
        b_input_ids = batch['input_ids'].to(device)
        b_attention_mask = batch['attention_mask'].to(device)
        b_labels = batch['labels'].to(device)

        with torch.no_grad():
            logits = model(input_ids=b_input_ids, attention_mask=b_attention_mask)
            loss = criterion(logits, b_labels)
            val_loss += loss.item()

            logits = torch.sigmoid(logits)
            logits = np.round(logits.cpu().numpy())
            labels = b_labels.cpu().numpy()

            pred.extend(logits)
            true.extend(labels)

    avg_val_loss = val_loss / len(val_dataloader)
    print('Val loss:', avg_val_loss)
    print('Val accuracy:', accuracy_score(true, pred))
    print('Val precision:', precision_score(true, pred, average='weighted'))
    print('Val recall:', recall_score(true, pred, average='weighted'))
    val_micro_f1_score = f1_score(true, pred, average='micro')
    print('Val micro f1 score:', val_micro_f1_score)
    val_macro_f1_score = f1_score(true, pred, average='macro')
    print('Val macro f1 score:', val_macro_f1_score)
    val_weighted_f1_score = f1_score(true, pred, average='weighted')
    print('Val weighted f1 score:', val_weighted_f1_score)

    if is_final_test:
        BEST_F1 = val_weighted_f1_score
        BEST_TRUE = true
        BEST_PREDICTED = pred
    elif val_weighted_f1_score > BEST_F1:
        BEST_F1 = val_weighted_f1_score
        BEST_TRUE = true
        BEST_PREDICTED = pred

    return val_weighted_f1_score

def train(model, train_dataloader, val_dataloader, criterion, optimizer, scheduler, epoch):
    global device
    nv = Config().N_VALIDATE_DUR_TRAIN
    temp = len(train_dataloader) // nv
    temp = temp - (temp % 100)
    validate_at_steps = [temp * x for x in range(1, nv + 1)]
    train_loss = 0

    for step, batch in enumerate(tqdm(train_dataloader, desc='Epoch ' + str(epoch))):
        model.train()
        b_input_ids = batch['input_ids'].to(device)
        b_attention_mask = batch['attention_mask'].to(device)
        b_labels = batch['labels'].to(device)

        optimizer.zero_grad()
        logits = model(input_ids=b_input_ids, attention_mask=b_attention_mask)
        loss = criterion(logits, b_labels)
        train_loss += loss.item()
        loss.backward()
        optimizer.step()
        scheduler.step()

        if step in validate_at_steps:
            print(f'-- Step: {step}')
            _ = val(model, val_dataloader, criterion)

    avg_train_loss = train_loss / len(train_dataloader)
    print('Training loss:', avg_train_loss)

def run():
    global train_data, val_data, test_data, train_dataloader, val_dataloader, test_dataloader, model
    torch.manual_seed(Config().SEED)
    criterion = nn.BCEWithLogitsLoss()

    # Set up the optimizer
    if Config().FULL_FINETUNING:
        param_optimizer = list(model.named_parameters())
        no_decay = ["bias", "LayerNorm.bias", "LayerNorm.weight"]
        optimizer_parameters = [
            {
                "params": [p for n, p in param_optimizer if not any(nd in n for nd in no_decay)],
                "weight_decay": 0.001,
            },
            {
                "params": [p for n, p in param_optimizer if any(nd in n for nd in no_decay)],
                "weight_decay": 0.0,
            },
        ]
        optimizer = optim.AdamW(optimizer_parameters, lr=Config().LR)

    num_training_steps = len(train_dataloader) * Config().EPOCHS
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=num_training_steps)
    max_val_weighted_f1_score = float('-inf')

    for epoch in range(Config().EPOCHS):
        train(model, train_dataloader, val_dataloader, criterion, optimizer, scheduler, epoch)
        val_weighted_f1_score = val(model, val_dataloader, criterion)
        if Config().SAVE_BEST_ONLY:
            if val_weighted_f1_score > max_val_weighted_f1_score:
                best_model = copy.deepcopy(model)
                model_name = 'secroberta_best_model'
                torch.save(best_model.state_dict(), model_name + '.pt')
                print(f'--- Best Model. Val: {max_val_weighted_f1_score} -> {val_weighted_f1_score}')
                max_val_weighted_f1_score = val_weighted_f1_score

    return best_model, max_val_weighted_f1_score

################################################################
# Main function

def main():
    global train_data, val_data, test_data, train_dataloader, val_dataloader, test_dataloader, model, device

    print("Using device:", torch.cuda.get_device_name() if torch.cuda.is_available() else "CPU")

    project_dir = 'scripts/supervised/datasets/enriched_to_technique/'
    config = Config()

    # Read CSV files
    df_train = pd.read_csv(project_dir + 'enriched_train_val_data.csv')
    print("Train data shape:", df_train.shape)
    print(df_train)
    df_val = pd.read_csv(project_dir + 'enriched_train_val_data.csv')
    print("Validation data shape:", df_val.shape)
    df_test = pd.read_csv(project_dir + 'enriched_test_data.csv')
    print("Test data shape:", df_test.shape)

    # Create datasets and dataloaders
    train_data = TransformerDataset(df_train, range(len(df_train)))
    print("Train Data Transformer:", train_data)
    val_data = TransformerDataset(df_val, range(len(df_val)))
    print("Val Data Transformer:", val_data)
    test_data = TransformerDataset(df_test, range(len(df_test)))
    print("Test Data Transformer:", test_data)

    train_dataloader = DataLoader(train_data, batch_size=Config().BATCH_SIZE, num_workers=0)
    print("Train Dataloader:", train_dataloader)
    val_dataloader = DataLoader(val_data, batch_size=Config().BATCH_SIZE, num_workers=0)
    print("Val Dataloader:", val_dataloader)
    test_dataloader = DataLoader(test_data, batch_size=Config().BATCH_SIZE, num_workers=0)
    print("Test Dataloader:", test_dataloader)

    # Optional: print shapes of one batch
    b = next(iter(train_dataloader))
    for k, v in b.items():
        print(f'{k} shape: {v.shape}')

    device = Config().DEVICE
    model = Model()
    model.to(device)

    best_model, best_val_weighted_f1_score = run()

    print("------Validation results --------")
    print("Best Weighted F1:", BEST_F1)

    # For computing per-class metrics we now need to generate a proper multi–hot DataFrame.
    # Create a list of technique names (here simply using their index as a string)
    technique_columns = [str(i) for i in range(Config().NUM_LABELS)]
    # Convert the training labels into a DataFrame for visualization purposes.
    train_labels = get_labels(df_train)
    y_train_df = pd.DataFrame(train_labels, columns=technique_columns)

    print("F1 scores per class")
    f1_best_metrics = compute_metrics(BEST_PREDICTED, BEST_TRUE, f1_score, technique_columns, 14)
    print("Recall scores per class")
    recall_best_metrics = compute_metrics(BEST_PREDICTED, BEST_TRUE, recall_score, technique_columns, 14)
    print("Precision scores per class")
    precision_best_metrics = compute_metrics(BEST_PREDICTED, BEST_TRUE, precision_score, technique_columns, 14)
    print("Accuracy scores per class")
    acc_best_metrics = compute_metrics(BEST_PREDICTED, BEST_TRUE, accuracy_score, technique_columns, 14)

    print_F1_based_on_distribution(BEST_PREDICTED, BEST_TRUE, y_train_df, technique_columns)

    print("------Testing results --------")
    test_weighted_f1_score = val(model, test_dataloader, nn.BCEWithLogitsLoss(), True)
    print("Test Weighted F1:", BEST_F1)

    f1_metrics = compute_metrics(BEST_PREDICTED, BEST_TRUE, f1_score, technique_columns, 14)
    print("F1 metrics:\n", f1_metrics)
    recall_metrics = compute_metrics(BEST_PREDICTED, BEST_TRUE, recall_score, technique_columns, 14)
    print("Recall metrics:\n", recall_metrics)
    precision_metrics = compute_metrics(BEST_PREDICTED, BEST_TRUE, precision_score, technique_columns, 14)
    print("Precision metrics:\n", precision_metrics)
    acc_metrics = compute_metrics(BEST_PREDICTED, BEST_TRUE, accuracy_score, technique_columns, 14)
    print("Accuracy metrics:\n", acc_metrics)

    print_F1_based_on_distribution(BEST_PREDICTED, BEST_TRUE, y_train_df, technique_columns)

    print("Class counts (true):")
    class_counts_true = np.sum(BEST_TRUE, axis=0)
    print(class_counts_true)
    print("Class counts (predicted):")
    class_counts_pred = np.sum(BEST_PREDICTED, axis=0)
    print(class_counts_pred)

    conf_matrix = multilabel_confusion_matrix(BEST_TRUE, BEST_PREDICTED)
    for i, matrix in enumerate(conf_matrix):
        print(f"Confusion Matrix for Class {i}:\n{matrix}\n")

if __name__ == "__main__":
    main()
