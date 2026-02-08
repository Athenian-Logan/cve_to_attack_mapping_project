import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch import optim
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm
import re
import copy
import sys
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    multilabel_confusion_matrix
)
from transformers import (
    AutoTokenizer, AutoModel, get_linear_schedule_with_warmup
)

# ---------------------------------------------------------
# 1. Configuration & Global State
# ---------------------------------------------------------
class Config:
    def __init__(self):
        self.SEED = 42
        self.MODEL_PATH = 'jackaduma/SecRoBERTa'
        self.NUM_LABELS = 14
        self.TOKENIZER = AutoTokenizer.from_pretrained(self.MODEL_PATH)
        self.MAX_LENGTH = 320

        # ✅ OPTUNA BEST
        self.BATCH_SIZE = 16
        self.LR = 5.6304809477691835e-05
        self.EPOCHS = 5
        self.N_VALIDATE_DUR_TRAIN = 3

        self.TRANSFORMER_DROPOUT = 0.17541571246097215
        self.NUMERIC_HIDDEN = 64
        self.NUMERIC_DROPOUT = 0.02833849086637827

        self.DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

BEST_F1 = 0
BEST_TRUE = []
BEST_PREDICTED = []

# ---------------------------------------------------------
# 2. Feature Engineering Helpers
# ---------------------------------------------------------
CVSS_IMPACT_MAP_V3 = {"N": 0.0, "L": 0.22, "H": 0.56}
CVSS_IMPACT_MAP_V2 = {"N": 0.0, "P": 0.275, "C": 0.66}

def parse_cvss(cvss):
    cont = torch.tensor([0.0, 0.0, 0.0])  # C, I, A
    cat = torch.tensor([0, 0, 0, 0, 0])   # AV, AC, PR, UI, Scope
    if not isinstance(cvss, str) or len(cvss) < 5: return cont, cat
    
    av_map, ac_map, pr_map, ui_map, s_map = {"N":0,"A":1,"L":2,"P":3}, {"L":0,"M":1,"H":2}, {"N":0,"L":1,"H":2}, {"N":0,"R":1}, {"U":0,"C":1}

    try:
        parts = dict(p.split(":") for p in cvss.split("/") if ":" in p)
        if cvss.startswith("CVSS:3"):
            cont = torch.tensor([CVSS_IMPACT_MAP_V3.get(parts.get(k, "N"), 0.0) for k in ["C", "I", "A"]])
            cat = torch.tensor([av_map.get(parts.get("AV", "N"), 0), ac_map.get(parts.get("AC", "L"), 0),
                                pr_map.get(parts.get("PR", "N"), 0), ui_map.get(parts.get("UI", "N"), 0),
                                s_map.get(parts.get("S", "U"), 0)])
        else:
            cont = torch.tensor([CVSS_IMPACT_MAP_V2.get(parts.get(k, "N"), 0.0) for k in ["C", "I", "A"]])
            cat = torch.tensor([av_map.get(parts.get("AV", "N"), 0), ac_map.get(parts.get("AC", "L"), 0),
                                pr_map.get(parts.get("Au", "N"), 0), 0, 0])
    except: pass
    return cont, cat

def extract_cpe_type(text):
    t = str(text).lower()
    return 0 if "operating system" in t else 1 if "application" in t else 2 if "hardware" in t else 3

def clean_abstract(text):
    text = re.sub(r"\d+(\.\d+)+", "version", str(text))
    return re.sub(r'CVE-\d{1,5}-\d{1,5}', "CVE", text)

def clean_cpe_text(text):
    match = re.search(
        r"The CVE affects (?P<vendor>[^ ]+) (?P<product>[^ ]+) (?P<type>Operating System|Application|Hardware)\.",
        str(text)
    )
    if match:
        vendor, product, _ = match.groups()
        return f"The CVE affects {vendor} {product}."
    return str(text)

# ---------------------------------------------------------
# 3. Multi-Modal Dataset
# ---------------------------------------------------------
class MultiModalDataset(Dataset):
    def __init__(self, df, indices):
        df = df.iloc[indices]
        self.texts = df['Text'].apply(clean_abstract).tolist()
        self.cwes = df['CWE'].fillna("Unknown CWE").tolist()
        self.cpe_desc = df['CPE'].apply(clean_cpe_text).tolist()
        self.epss = df['EPSS'].astype(float).tolist()
        self.cvss_raw = df['CVSS'].tolist()

        # ALWAYS load labels
        self.labels = df.iloc[:, 6:].values

        self.tokenizer = Config().TOKENIZER
        self.max_length = Config().MAX_LENGTH

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, index):
        # Concatenate text with SHAP tags. EPSS and CVSS are REMOVED from the string.
        raw_text = (
            "[ABSTRACT] " + str(self.texts[index]) +
            " [CWE] " + str(self.cwes[index]) +
            " [CPE] " + str(self.cpe_desc[index])
        )
        
        tokenized = self.tokenizer.encode_plus(
            raw_text, max_length=self.max_length, padding="max_length",
            truncation=True, return_attention_mask=True, return_tensors='pt'
        )
        cvss_cont, cvss_cat = parse_cvss(self.cvss_raw[index])
        
        item = {
            'input_ids': tokenized['input_ids'].squeeze().long(),
            'attention_mask': tokenized['attention_mask'].squeeze().long(),
            'epss': torch.tensor(self.epss[index], dtype=torch.float),
            'cvss_cont': cvss_cont.float(),
            'cvss_cat': cvss_cat.long(),
            'cpe_type': torch.tensor(extract_cpe_type(self.cpe_desc[index]), dtype=torch.long)
        }
        item['labels'] = torch.Tensor(self.labels[index]).float()
        return item

# ---------------------------------------------------------
# 4. Multi-Modal Model Architecture
# ---------------------------------------------------------
class MultiModalModel(nn.Module):
    def __init__(self):
        super().__init__()

        self.transformer = AutoModel.from_pretrained(Config().MODEL_PATH)
        self.dropout = nn.Dropout(Config().TRANSFORMER_DROPOUT)

        self.av_emb = nn.Embedding(4, 4)
        self.ac_emb = nn.Embedding(3, 2)
        self.pr_emb = nn.Embedding(3, 2)
        self.ui_emb = nn.Embedding(2, 2)
        self.s_emb = nn.Embedding(2, 2)
        self.cpe_emb = nn.Embedding(4, 4)

        self.numeric_mlp = nn.Sequential(
            nn.Linear(20, Config().NUMERIC_HIDDEN),
            nn.ReLU(),
            nn.Dropout(Config().NUMERIC_DROPOUT)
        )

        self.output = nn.Linear(768 + Config().NUMERIC_HIDDEN, Config().NUM_LABELS)

    def forward(self, input_ids, attention_mask, epss, cvss_cont, cvss_cat, cpe_type):
        _, o2 = self.transformer(input_ids=input_ids, attention_mask=attention_mask, return_dict=False)
        text_feats = self.dropout(o2)

        embs = torch.cat([self.av_emb(cvss_cat[:, 0]), self.ac_emb(cvss_cat[:, 1]),
                          self.pr_emb(cvss_cat[:, 2]), self.ui_emb(cvss_cat[:, 3]),
                          self.s_emb(cvss_cat[:, 4]), self.cpe_emb(cpe_type)], dim=1)

        num_feats = self.numeric_mlp(torch.cat([epss.unsqueeze(1), cvss_cont, embs], dim=1))
        return self.output(torch.cat([text_feats, num_feats], dim=1))

# ---------------------------------------------------------
# 5. Training & Validation Utilities
# ---------------------------------------------------------
def val(model, dataloader, criterion, split_name="Val"):
    model.eval()
    val_loss, true, pred = 0, [], []

    for batch in dataloader:
        batch = {k: v.to(device) if isinstance(v, torch.Tensor) else v
                 for k, v in batch.items()}

        with torch.no_grad():
            logits = model(
                batch['input_ids'],
                batch['attention_mask'],
                batch['epss'],
                batch['cvss_cont'],
                batch['cvss_cat'],
                batch['cpe_type']
            )

            probs = torch.sigmoid(logits)
            preds = (probs > 0.5).int()

            pred.append(preds.cpu().numpy())
            true.append(batch['labels'].cpu().numpy())
            val_loss += criterion(logits, batch['labels']).item()

    true = np.vstack(true)
    pred = np.vstack(pred)

    print(f"\n[{split_name} RESULTS]")
    print(f"Loss: {val_loss / len(dataloader):.4f}")
    print(f"Micro F1:   {f1_score(true, pred, average='micro', zero_division=0):.4f}")
    print(f"Macro F1:   {f1_score(true, pred, average='macro', zero_division=0):.4f}")
    print(f"Weighted F1:{f1_score(true, pred, average='weighted', zero_division=0):.4f}")

    return true, pred

def train(model, train_dataloader, val_dataloader, criterion, optimizer, scheduler, epoch):
    global device
    nv = Config().N_VALIDATE_DUR_TRAIN
    total_steps = len(train_dataloader)
    
    # Validation step logic matching the 100/200/300 step format
    temp = total_steps // nv
    temp = temp - (temp % 100) if temp > 100 else temp
    validate_at_steps = [temp * x for x in range(1, nv + 1)]
    
    model.train()
    for step, batch in enumerate(tqdm(train_dataloader, desc=f'Epoch {epoch}', file=sys.stdout)):
        batch = {k: v.to(device) if isinstance(v, torch.Tensor) else v for k, v in batch.items()}
        optimizer.zero_grad()
        
        logits = model(batch['input_ids'], batch['attention_mask'], batch['epss'], 
                       batch['cvss_cont'], batch['cvss_cat'], batch['cpe_type'])
        
        loss = criterion(logits, batch['labels'])
        loss.backward()
        optimizer.step()
        scheduler.step()

        if step in validate_at_steps:
            tqdm.write(f"\n-- Step: {step}")
            val(model, val_dataloader, criterion)
            model.train()

# ---------------------------------------------------------
# 6. Main Runner
# ---------------------------------------------------------
def main():
    global device, model, BEST_F1, BEST_TRUE, BEST_PREDICTED
    config = Config()
    device = config.DEVICE
    print(f"Using device: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}")

    project_dir = 'scripts/supervised/datasets/multi_modal/'
    df_full = pd.read_csv(project_dir + 'enriched_full_data.csv')

    # Extract CVE year
    df_full['year'] = df_full['ID'].str.extract(r'CVE-(\d{4})').astype(int)

    # Temporal split
    df_train = df_full[df_full['year'] <= 2021]
    df_val   = df_full[df_full['year'] == 2022]
    df_test  = df_full[df_full['year'] >= 2023]

    print(f"Train years: ≤2021 → {df_train.shape}")
    print(f"Val years: 2022 → {df_val.shape}")
    print(f"Test years: ≥2023 → {df_test.shape}")

    df_train = df_train.drop(columns=["year"])
    df_val   = df_val.drop(columns=["year"])
    df_test  = df_test.drop(columns=["year"])

    train_ds = MultiModalDataset(df_train, range(len(df_train)))
    val_ds   = MultiModalDataset(df_val, range(len(df_val)))
    test_ds = MultiModalDataset(df_test, range(len(df_test)))

    # Printing Dataset object addresses as seen in your logs
    print(f"Train Data Transformer: {train_ds}")
    print(f"Val Data Transformer: {val_ds}")
    print(f"Test Data Transformer: {test_ds}")

    train_loader = DataLoader(train_ds, batch_size=config.BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=config.BATCH_SIZE)
    test_loader = DataLoader(test_ds, batch_size=config.BATCH_SIZE)

    print(f"Train Dataloader: {train_loader}")
    print(f"Val Dataloader: {val_loader}")
    print(f"Test Dataloader: {test_loader}")

    # Printing batch tensor shapes
    fb = next(iter(train_loader))
    print(f"input_ids shape: {fb['input_ids'].shape}\nattention_mask shape: {fb['attention_mask'].shape}\nlabels shape: {fb['labels'].shape}")

    model = MultiModalModel().to(device)
    optimizer = optim.AdamW(model.parameters(), lr=config.LR, weight_decay=0.01)
    scheduler = get_linear_schedule_with_warmup(optimizer, 0, len(train_loader) * config.EPOCHS)
    criterion = nn.BCEWithLogitsLoss()

    BEST_F1 = 0
    for epoch in range(config.EPOCHS):
        train(model, train_loader, val_loader, criterion, optimizer, scheduler, epoch)
        val(model, val_loader, criterion)

    torch.save(model.state_dict(), 'Supervised/models/time_series_split_multi_modal_tuned.pt')

    TACTICS = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]

    print("\nFINAL EVALUATION ON TEST SET")
    y_true, y_pred = val(model, test_loader, criterion, split_name="Test")

    print("\nPer-Tactic F1 Scores:")
    per_tactic_f1 = f1_score(y_true, y_pred, average=None, zero_division=0)
    for tactic, score in zip(TACTICS, per_tactic_f1):
        print(f"{tactic:25s}: {score:.4f}")

    cms = multilabel_confusion_matrix(y_true, y_pred)

    for i, tactic in enumerate(TACTICS):
        tn, fp, fn, tp = cms[i].ravel()
        print(f"\n{tactic}")
        print(f"TP={tp} FP={fp} FN={fn} TN={tn}")



if __name__ == "__main__":
    main()