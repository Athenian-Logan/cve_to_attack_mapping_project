import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import re
from collections import defaultdict
from tqdm import tqdm
from transformers import AutoTokenizer, AutoModel
import warnings
warnings.filterwarnings("ignore")

# =========================================================
# CONFIG
# =========================================================
MODEL_PATH = "jackaduma/SecRoBERTa"

MODEL_WEIGHTS = "Supervised/models/non_tuned_multi_modal_secroberta_final.pt" # non fine tuned multi modal analysis - need to do
"""
MODEL_WEIGHTS = "Supervised/models/multi_modal_secroberta_final.pt" # fine tuned multi modal analysis - done
"""
DATA_PATH = "scripts/supervised/datasets/multi_modal/enriched_train_val_data.csv"
OUTPUT_CSV = "Supervised/SHAP/global_analysis_multi_modal/untuned_multimodal_feature_importance_by_tactic.csv" # added untuned to name for now

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MAX_LENGTH = 320
NUM_LABELS = 14
MAX_SAMPLES = 200   # CPU friendly

TACTICS = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact'
]

# =========================================================
# TOKENIZER
# =========================================================
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)

# =========================================================
# CVSS PARSING (same as training)
# =========================================================
CVSS_IMPACT_MAP_V3 = {"N": 0.0, "L": 0.22, "H": 0.56}

def parse_cvss(cvss):
    cont = torch.tensor([0.0, 0.0, 0.0])
    cat = torch.tensor([0, 0, 0, 0, 0])

    if not isinstance(cvss, str):
        return cont, cat

    av_map = {"N":0,"A":1,"L":2,"P":3}
    ac_map = {"L":0,"M":1,"H":2}
    pr_map = {"N":0,"L":1,"H":2}
    ui_map = {"N":0,"R":1}
    s_map  = {"U":0,"C":1}

    try:
        parts = dict(p.split(":") for p in cvss.split("/") if ":" in p)
        cont = torch.tensor([
            CVSS_IMPACT_MAP_V3.get(parts.get("C","N"),0.0),
            CVSS_IMPACT_MAP_V3.get(parts.get("I","N"),0.0),
            CVSS_IMPACT_MAP_V3.get(parts.get("A","N"),0.0)
        ])
        cat = torch.tensor([
            av_map.get(parts.get("AV","N"),0),
            ac_map.get(parts.get("AC","L"),0),
            pr_map.get(parts.get("PR","N"),0),
            ui_map.get(parts.get("UI","N"),0),
            s_map.get(parts.get("S","U"),0)
        ])
    except:
        pass

    return cont, cat

def extract_cpe_type(text):
    t = str(text).lower()
    if "operating system" in t: return 0
    if "application" in t: return 1
    if "hardware" in t: return 2
    return 3

# =========================================================
# MULTIMODAL MODEL (INLINE)
# =========================================================
class MultiModalModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.transformer = AutoModel.from_pretrained(MODEL_PATH)
        self.dropout = nn.Dropout(0.1)

        self.av_emb  = nn.Embedding(4, 4)
        self.ac_emb  = nn.Embedding(3, 2)
        self.pr_emb  = nn.Embedding(3, 2)
        self.ui_emb  = nn.Embedding(2, 2)
        self.s_emb   = nn.Embedding(2, 2)
        self.cpe_emb = nn.Embedding(4, 4)

        self.numeric_mlp = nn.Sequential(
            nn.Linear(20, 64),
            nn.ReLU()
        )

        self.output = nn.Linear(768 + 64, NUM_LABELS)

    def forward(self, input_ids, attention_mask, epss, cvss_cont, cvss_cat, cpe_type):
        _, pooled = self.transformer(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict=False
        )
        text_feats = self.dropout(pooled)

        embs = torch.cat([
            self.av_emb(cvss_cat[:,0]),
            self.ac_emb(cvss_cat[:,1]),
            self.pr_emb(cvss_cat[:,2]),
            self.ui_emb(cvss_cat[:,3]),
            self.s_emb(cvss_cat[:,4]),
            self.cpe_emb(cpe_type)
        ], dim=1)

        numeric = torch.cat([epss.unsqueeze(1), cvss_cont, embs], dim=1)
        numeric_feats = self.numeric_mlp(numeric)

        return self.output(torch.cat([text_feats, numeric_feats], dim=1))

# =========================================================
# LOAD MODEL
# =========================================================
model = MultiModalModel().to(DEVICE)
model.load_state_dict(torch.load(MODEL_WEIGHTS, map_location=DEVICE))
model.eval()

# =========================================================
# TOKENIZATION WITH FEATURE SPANS
# =========================================================
def tokenize_with_spans(row):
    sections = [
        ("ABSTRACT", "[ABSTRACT] " + str(row["Text"])),
        ("CWE", "[CWE] " + str(row["CWE"])),
        ("CPE", "[CPE] " + str(row["CPE"]))
    ]

    tokens, spans = [], {}
    cursor = 1

    for feat, txt in sections:
        toks = tokenizer.tokenize(txt)
        tokens.extend(toks)
        spans[feat] = (cursor, cursor + len(toks))
        cursor += len(toks)

    input_ids = [tokenizer.cls_token_id] + tokenizer.convert_tokens_to_ids(tokens)
    input_ids = input_ids[:MAX_LENGTH-1] + [tokenizer.sep_token_id]
    attention_mask = [1] * len(input_ids)

    pad = MAX_LENGTH - len(input_ids)
    input_ids += [tokenizer.pad_token_id] * pad
    attention_mask += [0] * pad

    return (
        spans,
        torch.tensor([input_ids]).to(DEVICE),
        torch.tensor([attention_mask]).to(DEVICE)
    )

# =========================================================
# ATTENTION-BASED TEXT ATTRIBUTION
# =========================================================
def explain_text(batch):
    with torch.no_grad():
        out = model.transformer(
            input_ids=batch["input_ids"],
            attention_mask=batch["attention_mask"],
            output_attentions=True,
            return_dict=True
        )

    attn = out.attentions[-1].mean(dim=1)[0, 0]
    return attn.cpu().numpy()

# =========================================================
# NUMERIC GRADIENT ATTRIBUTION
# =========================================================
def explain_numeric(batch, tactic_idx):
    for k in ["epss", "cvss_cont"]:
        batch[k].requires_grad_(True)

    logits = model(**batch)
    prob = torch.sigmoid(logits)[0, tactic_idx]

    model.zero_grad()
    prob.backward()

    return {
        "EPSS": abs(batch["epss"].grad.item()),
        "CVSS_C": abs(batch["cvss_cont"].grad[0,0].item()),
        "CVSS_I": abs(batch["cvss_cont"].grad[0,1].item()),
        "CVSS_A": abs(batch["cvss_cont"].grad[0,2].item())
    }

# =========================================================
# MAIN SHAP LOOP
# =========================================================
df = pd.read_csv(DATA_PATH).sample(n=MAX_SAMPLES, random_state=42)

global_scores = {t: defaultdict(float) for t in TACTICS}
counts = defaultdict(int)

for _, row in tqdm(df.iterrows(), total=len(df)):
    spans, ids, mask = tokenize_with_spans(row)
    cvss_cont, cvss_cat = parse_cvss(row["CVSS"])

    batch = {
        "input_ids": ids,
        "attention_mask": mask,
        "epss": torch.tensor([row["EPSS"]], device=DEVICE),
        "cvss_cont": cvss_cont.unsqueeze(0).to(DEVICE),
        "cvss_cat": cvss_cat.unsqueeze(0).to(DEVICE),
        "cpe_type": torch.tensor([extract_cpe_type(row["CPE"])], device=DEVICE)
    }

    with torch.no_grad():
        probs = torch.sigmoid(model(**batch))[0]

    attn = explain_text(batch)

    for i, p in enumerate(probs):
        if p < 0.5:
            continue

        tactic = TACTICS[i]
        counts[tactic] += 1

        for feat, (s,e) in spans.items():
            global_scores[tactic][f"TEXT_{feat}"] += attn[s:e].sum()

        for k,v in explain_numeric(batch, i).items():
            global_scores[tactic][k] += v

# =========================================================
# NORMALIZE + EXPORT
# =========================================================
rows = []
for tactic, feats in global_scores.items():
    total = sum(feats.values())
    if total == 0:
        continue
    for f,v in feats.items():
        rows.append({
            "Tactic": tactic,
            "Feature": f,
            "Importance (%)": 100*v/total,
            "Samples": counts[tactic]
        })

pd.DataFrame(rows).to_csv(OUTPUT_CSV, index=False)
print(f"Saved → {OUTPUT_CSV}")
