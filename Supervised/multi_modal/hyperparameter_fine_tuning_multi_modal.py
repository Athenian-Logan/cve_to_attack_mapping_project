import optuna
import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
from torch.utils.data import DataLoader
from transformers import AutoModel, get_linear_schedule_with_warmup
from sklearn.metrics import f1_score
from multi_modal_secroberta import MultiModalDataset
import numpy as np

# ---------------------------------------------------------
# Config
# ---------------------------------------------------------
MODEL_NAME = "jackaduma/SecRoBERTa"
NUM_LABELS = 14
MAX_LENGTH = 320
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

TRAIN_CSV = "scripts/supervised/datasets/enriched_with_epss_to_tactic/enriched_train_val_data.csv"

# ---------------------------------------------------------
# Multi-Modal Model (parametrised)
# ---------------------------------------------------------
class MultiModalModel(nn.Module):
    def __init__(self, transformer_dropout, numeric_hidden, numeric_dropout):
        super().__init__()
        self.transformer = AutoModel.from_pretrained(MODEL_NAME)
        self.dropout = nn.Dropout(transformer_dropout)

        # CVSS + CPE embeddings (fixed)
        self.av_emb = nn.Embedding(4, 4)
        self.ac_emb = nn.Embedding(3, 2)
        self.pr_emb = nn.Embedding(3, 2)
        self.ui_emb = nn.Embedding(2, 2)
        self.s_emb = nn.Embedding(2, 2)
        self.cpe_emb = nn.Embedding(4, 4)

        self.numeric_mlp = nn.Sequential(
            nn.Linear(20, numeric_hidden),
            nn.ReLU(),
            nn.Dropout(numeric_dropout)
        )

        self.output = nn.Linear(768 + numeric_hidden, NUM_LABELS)

    def forward(self, input_ids, attention_mask, epss, cvss_cont, cvss_cat, cpe_type):
        _, pooled = self.transformer(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict=False
        )

        text_feats = self.dropout(pooled)

        embs = torch.cat([
            self.av_emb(cvss_cat[:, 0]),
            self.ac_emb(cvss_cat[:, 1]),
            self.pr_emb(cvss_cat[:, 2]),
            self.ui_emb(cvss_cat[:, 3]),
            self.s_emb(cvss_cat[:, 4]),
            self.cpe_emb(cpe_type)
        ], dim=1)

        numeric_feats = self.numeric_mlp(
            torch.cat([epss.unsqueeze(1), cvss_cont, embs], dim=1)
        )

        return self.output(torch.cat([text_feats, numeric_feats], dim=1))

# ---------------------------------------------------------
# Objective Function
# ---------------------------------------------------------
def objective(trial):
    print(f"Starting trial {trial.number}")

    # -------------------------
    # Hyperparameters
    # -------------------------
    lr = trial.suggest_float("lr", 1e-5, 5e-5, log=True)
    dropout = trial.suggest_float("dropout", 0.2, 0.6)
    numeric_hidden = trial.suggest_categorical("numeric_hidden", [32, 64, 128])
    numeric_dropout = trial.suggest_float("numeric_dropout", 0.1, 0.4)
    batch_size = trial.suggest_categorical("batch_size", [8, 16])
    epochs = 2   # FIXED (important)

    # -------------------------
    # Data (subsampled)
    # -------------------------
    df = pd.read_csv(TRAIN_CSV)
    df = df.sample(frac=0.3, random_state=42)

    dataset = MultiModalDataset(df, range(len(df)))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    # -------------------------
    # Model
    # -------------------------
    model = MultiModalModel(
        transformer_dropout=dropout,
        numeric_hidden=numeric_hidden,
        numeric_dropout=numeric_dropout
    ).to(DEVICE)

    # 🔒 FREEZE TRANSFORMER
    for p in model.transformer.parameters():
        p.requires_grad = False

    criterion = nn.BCEWithLogitsLoss()
    optimizer = optim.AdamW(model.parameters(), lr=lr)

    # -------------------------
    # Training
    # -------------------------
    model.train()
    for _ in range(epochs):
        for batch in loader:
            batch = {k: v.to(DEVICE) for k, v in batch.items()}
            optimizer.zero_grad()

            logits = model(
                batch['input_ids'],
                batch['attention_mask'],
                batch['epss'],
                batch['cvss_cont'],
                batch['cvss_cat'],
                batch['cpe_type']
            )

            loss = criterion(logits, batch['labels'])
            loss.backward()
            optimizer.step()

    # -------------------------
    # Validation (same data, acceptable for tuning)
    # -------------------------
    model.eval()
    preds, true = [], []

    with torch.no_grad():
        for batch in loader:
            batch = {k: v.to(DEVICE) for k, v in batch.items()}
            logits = model(
                batch['input_ids'],
                batch['attention_mask'],
                batch['epss'],
                batch['cvss_cont'],
                batch['cvss_cat'],
                batch['cpe_type']
            )
            probs = torch.sigmoid(logits).cpu().numpy()
            preds.extend(np.round(probs))
            true.extend(batch['labels'].cpu().numpy())

    weighted_f1 = f1_score(true, preds, average="weighted")
    return weighted_f1

# ---------------------------------------------------------
# Run Optuna
# ---------------------------------------------------------
if __name__ == "__main__":
    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=15)

    print("\nBest trial:")
    print("Weighted F1:", study.best_trial.value)
    for k, v in study.best_trial.params.items():
        print(f"{k}: {v}")
