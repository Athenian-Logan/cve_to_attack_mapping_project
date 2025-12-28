import torch
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from transformers import AutoTokenizer, AutoModel
from collections import defaultdict
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore")

# -----------------------
# CONFIG
# -----------------------
MODEL_PATH = "jackaduma/SecRoBERTa"
MODEL_WEIGHTS = "Supervised/models/secroberta_best_model_shap_ready.pt"
NUM_LABELS = 14
MAX_LENGTH = 320
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

DATA_PATH = "scripts/supervised/datasets/enriched_with_epss_to_tactic/enriched_train_val_data.csv"
OUTPUT_CSV = "Supervised/SHAP/global_analysis/global_feature_importance_by_tactic.csv"
SELECTED_CVES_CSV = "Supervised/SHAP/global_analysis/selected_cves_for_analysis.csv"

# Limit to reasonable sample size for global analysis
MAX_SAMPLES_FOR_GLOBAL = 200  # Adjust based on your patience

# -----------------------
# Tokenizer
# -----------------------
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)

# -----------------------
# Model definition
# -----------------------
class Model(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.transformer_model = AutoModel.from_pretrained(MODEL_PATH)
        self.dropout = torch.nn.Dropout(0.4864913766068174)
        self.output = torch.nn.Linear(768, NUM_LABELS)

    def forward(self, input_ids, attention_mask):
        _, pooled = self.transformer_model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict=False
        )
        return self.output(self.dropout(pooled))

# -----------------------
# Load trained model
# -----------------------
model = Model().to(DEVICE)
model.load_state_dict(
    torch.load(MODEL_WEIGHTS, map_location=DEVICE, weights_only=True)
)
model.eval()

# -----------------------
# FAST: Gradient-based importance (much faster than occlusion)
# -----------------------
def explain_with_gradients(input_ids, attention_mask, tactic_idx):
    """Fast gradient-based explanation."""
    input_ids.requires_grad_(True)
    
    # Forward pass
    logits = model(input_ids, attention_mask)
    probs = torch.sigmoid(logits)
    
    # Get probability for target tactic
    target_prob = probs[0, tactic_idx]
    
    # Compute gradients
    model.zero_grad()
    target_prob.backward()
    
    # Get gradient magnitudes
    grad_magnitudes = torch.abs(input_ids.grad).squeeze().cpu().numpy()
    
    return grad_magnitudes

# -----------------------
# FAST: Attention-based importance (even faster)
# -----------------------
def explain_with_attention(input_ids, attention_mask):
    """Fast attention-based explanation."""
    with torch.no_grad():
        outputs = model.transformer_model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_attentions=True,
            return_dict=False
        )
    
    # Get attention from last layer
    attentions = outputs[-1]
    last_layer_attentions = attentions[-1]
    
    # Average across attention heads
    avg_attention = last_layer_attentions.mean(dim=1).squeeze().cpu().numpy()
    
    # Use [CLS] token attention to other tokens
    cls_attention = avg_attention[0]
    
    return cls_attention

# -----------------------
# Tokenization with feature spans
# -----------------------
def tokenize_with_feature_spans(row):
    sections = [
        ("ABSTRACT", "[ABSTRACT] " + str(row["Text"])),
        ("EPSS", "[EPSS] " + str(row["EPSS"])),
        ("CVSS", "[CVSS] " + str(row["CVSS"])),
        ("CWE", "[CWE] " + str(row["CWE"])),
        ("CPE", "[CPE] " + str(row["CPE"]))
    ]

    all_tokens = []
    feature_map = []

    for feature, text in sections:
        toks = tokenizer.tokenize(text)
        all_tokens.extend(toks)
        feature_map.extend([feature] * len(toks))

    input_ids = tokenizer.convert_tokens_to_ids(all_tokens)
    input_ids = [tokenizer.cls_token_id] + input_ids + [tokenizer.sep_token_id]
    feature_map = [None] + feature_map + [None]

    if len(input_ids) > MAX_LENGTH:
        input_ids = input_ids[:MAX_LENGTH]
        feature_map = feature_map[:MAX_LENGTH]
        input_ids[-1] = tokenizer.sep_token_id
        feature_map[-1] = None
    else:
        pad_len = MAX_LENGTH - len(input_ids)
        input_ids += [tokenizer.pad_token_id] * pad_len
        feature_map += [None] * pad_len

    attention_mask = [1 if t != tokenizer.pad_token_id else 0 for t in input_ids]

    return (
        feature_map,
        torch.tensor([input_ids]).to(DEVICE),
        torch.tensor([attention_mask]).to(DEVICE),
    )

# -----------------------
# Aggregate token scores → feature scores
# -----------------------
def aggregate_by_feature(feature_map, scores):
    feature_scores = defaultdict(float)

    for feat, score in zip(feature_map, scores):
        if feat is not None:
            feature_scores[feat] += float(score)

    total = sum(feature_scores.values())
    if total > 0:
        for k in feature_scores:
            feature_scores[k] = (feature_scores[k] / total) * 100

    return feature_scores

# -----------------------
# Visualization
# -----------------------
def plot_feature_importance(feature_scores, tactic):
    features = list(feature_scores.keys())
    values = list(feature_scores.values())
    
    if sum(values) == 0:
        print(f"No feature importance calculated for {tactic}")
        return

    plt.figure(figsize=(8, 5))
    bars = plt.bar(features, values)
    plt.title(f"Global Feature Importance – {tactic}")
    plt.ylabel("Importance (%)")
    plt.xticks(rotation=45)
    plt.tight_layout()

    for bar, val in zip(bars, values):
        if val > 0:
            plt.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{val:.1f}%",
                ha="center",
                va="bottom",
            )

    plt.show()

# -----------------------
# Main: FAST Global analysis
# -----------------------
if __name__ == "__main__":
    # Load data
    df = pd.read_csv(DATA_PATH)
    original_count = len(df)
    
    # Take a subset for faster analysis
    selected_indices = []
    if len(df) > MAX_SAMPLES_FOR_GLOBAL:
        subset_df = df.sample(MAX_SAMPLES_FOR_GLOBAL, random_state=42)
        selected_indices = subset_df.index.tolist()
        df = subset_df
        print(f"Using subset of {MAX_SAMPLES_FOR_GLOBAL} samples for faster analysis")
        print(f"(Selected {MAX_SAMPLES_FOR_GLOBAL} out of {original_count} total samples)")
    else:
        selected_indices = df.index.tolist()
        print(f"Using all {len(df)} samples for analysis")
    
    # Save which CVEs were selected
    selected_cves_df = pd.DataFrame({
        'Original_Index': selected_indices,
        'CVE_ID': df['ID'].tolist(),
        'Text_Preview': df['Text'].str[:100].tolist()
    })
    selected_cves_df.to_csv(SELECTED_CVES_CSV, index=False)
    print(f"\nSaved selected CVEs to: {SELECTED_CVES_CSV}")
    print(f"First 10 selected CVEs:")
    print(selected_cves_df[['CVE_ID', 'Text_Preview']].head(10).to_string())
    
    tactics = [
        'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
        'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
        'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
        'Exfiltration', 'Impact'
    ]

    # We'll analyze using attention (fastest method)
    print(f"\nRunning FAST global analysis on {len(df)} samples...")
    print("Method: Attention-based (fastest)")
    
    global_importance = {t: defaultdict(float) for t in tactics}
    tactic_counts = defaultdict(int)
    
    # Process each sample
    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing samples"):
        try:
            feature_map, input_ids, attention_mask = tokenize_with_feature_spans(row)
            
            with torch.no_grad():
                probs = torch.sigmoid(model(input_ids, attention_mask))[0].cpu().numpy()
            
            # Get attention-based importance
            attention_scores = explain_with_attention(input_ids, attention_mask)
            
            # Get predicted tactics
            predicted = np.where(probs > 0.5)[0]
            if len(predicted) == 0:
                predicted = [int(np.argmax(probs))]
            
            # Assign attention importance to each predicted tactic
            for tactic_idx in predicted:
                tactic = tactics[tactic_idx]
                feature_scores = aggregate_by_feature(feature_map, attention_scores)
                
                for feat, val in feature_scores.items():
                    global_importance[tactic][feat] += val
                
                tactic_counts[tactic] += 1
                
        except Exception as e:
            print(f"\nError processing sample {idx} (CVE: {row['ID']}): {e}")
            continue
    
    # Normalize per tactic
    print("\nNormalizing results...")
    normalized = {}
    for tactic, feats in global_importance.items():
        if tactic_counts[tactic] > 0:
            # Average over samples
            normalized[tactic] = {k: v / tactic_counts[tactic] for k, v in feats.items()}
    
    # Export results
    rows = []
    for tactic, feats in normalized.items():
        for feat, val in feats.items():
            rows.append({
                "Tactic": tactic,
                "Feature": feat,
                "Importance (%)": val,
                "Sample_Count": tactic_counts[tactic]
            })
    
    result_df = pd.DataFrame(rows)
    result_df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSaved global feature importance to {OUTPUT_CSV}")
    
    # Show summary
    print("\n" + "="*60)
    print("GLOBAL FEATURE IMPORTANCE SUMMARY")
    print("="*60)
    
    # Show sample counts per tactic
    print("\nSamples contributing to each tactic:")
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            print(f"{tactic:<25} {count:>4} samples")
    
    # Group by tactic and show top features
    print("\nTop features per tactic:")
    for tactic in tactics:
        if tactic in normalized and tactic_counts[tactic] > 0:
            feat_scores = normalized[tactic]
            if feat_scores:
                sorted_features = sorted(feat_scores.items(), key=lambda x: x[1], reverse=True)
                top_feature = sorted_features[0]
                print(f"{tactic:<25} Top: {top_feature[0]:<15} ({top_feature[1]:.1f}%)")
    
    # Plot each tactic
    print("\nGenerating plots...")
    for tactic, feats in normalized.items():
        if tactic_counts[tactic] > 0:
            plot_feature_importance(feats, tactic)
    
    # Show overall statistics
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE - SUMMARY")
    print("="*60)
    print(f"Total CVEs analyzed: {len(df)}")
    print(f"CVEs selected saved to: {SELECTED_CVES_CSV}")
    print(f"Feature importance saved to: {OUTPUT_CSV}")
    
    # Show which tactics had the most/least samples
    tactics_with_samples = [(t, c) for t, c in tactic_counts.items() if c > 0]
    if tactics_with_samples:
        most_common = max(tactics_with_samples, key=lambda x: x[1])
        least_common = min(tactics_with_samples, key=lambda x: x[1])
        print(f"\nMost frequently predicted tactic: {most_common[0]} ({most_common[1]} samples)")
        print(f"Least frequently predicted tactic: {least_common[0]} ({least_common[1]} samples)")