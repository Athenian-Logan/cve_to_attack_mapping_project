import torch
import numpy as np
import pandas as pd
import re
import matplotlib.pyplot as plt
from transformers import AutoTokenizer, AutoModel
import warnings
warnings.filterwarnings('ignore')

# -----------------------
# CONFIG (must match training)
# -----------------------
MODEL_PATH = "jackaduma/SecRoBERTa"
MODEL_WEIGHTS = "Supervised/models/secroberta_best_model_shap_ready.pt"
NUM_LABELS = 14
MAX_LENGTH = 320
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)

# -----------------------
# Model definition (SAME AS TRAINING)
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
# FIXED: Tokenize with feature spans tracking
# -----------------------
def tokenize_with_feature_spans(row):
    """Tokenize each section separately and track which tokens belong to which feature."""
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
        # Tokenize this section
        toks = tokenizer.tokenize(text)
        all_tokens.extend(toks)
        feature_map.extend([feature] * len(toks))

    # Now convert tokens to input_ids with proper padding/truncation
    # First, convert tokens to ids
    input_ids = tokenizer.convert_tokens_to_ids(all_tokens)
    
    # Add special tokens: [CLS] at beginning, [SEP] at end
    input_ids = [tokenizer.cls_token_id] + input_ids + [tokenizer.sep_token_id]
    
    # Add None for special tokens in feature map
    feature_map = [None] + feature_map + [None]  # None for [CLS] and [SEP]
    
    # Truncate if needed
    if len(input_ids) > MAX_LENGTH:
        input_ids = input_ids[:MAX_LENGTH]
        feature_map = feature_map[:MAX_LENGTH]
        # Make sure last token is [SEP]
        input_ids[-1] = tokenizer.sep_token_id
        feature_map[-1] = None
    else:
        # Pad
        padding_length = MAX_LENGTH - len(input_ids)
        input_ids = input_ids + [tokenizer.pad_token_id] * padding_length
        feature_map = feature_map + [None] * padding_length
    
    # Create attention mask
    attention_mask = [1 if token_id != tokenizer.pad_token_id else 0 for token_id in input_ids]
    
    # Convert to tensors
    input_ids_tensor = torch.tensor([input_ids], dtype=torch.long).to(DEVICE)
    attention_mask_tensor = torch.tensor([attention_mask], dtype=torch.long).to(DEVICE)
    
    # Get tokens for display
    tokens = tokenizer.convert_ids_to_tokens(input_ids)
    
    return tokens, feature_map, input_ids_tensor, attention_mask_tensor

# -----------------------
# FIXED: Aggregate by feature using feature map
# -----------------------
def aggregate_by_feature(feature_map, scores):
    """Aggregate scores by feature using the precomputed feature map."""
    feature_scores = {}
    
    for feat, score in zip(feature_map, scores):
        if feat is None:  # Skip special tokens
            continue
        feature_scores.setdefault(feat, 0.0)
        feature_scores[feat] += float(score)
    
    # Normalize to percentages
    total = sum(feature_scores.values())
    if total > 0:
        for k in feature_scores:
            feature_scores[k] = (feature_scores[k] / total) * 100
    
    return feature_scores

# -----------------------
# Helper function to get predictions
# -----------------------
def get_predictions(input_ids, attention_mask):
    """Get model predictions for given input."""
    with torch.no_grad():
        logits = model(input_ids, attention_mask)
        probs = torch.sigmoid(logits)
    
    return probs.cpu().numpy()[0]

# -----------------------
# Method 1: Attention-based feature importance
# -----------------------
def explain_with_attention(input_ids, attention_mask):
    """Extract attention weights from the model."""
    # Get model outputs with attention
    with torch.no_grad():
        outputs = model.transformer_model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_attentions=True,
            return_dict=False
        )
    
    # Get tokens
    tokens = tokenizer.convert_ids_to_tokens(input_ids[0].cpu().numpy())
    
    # Extract attention from the last layer
    attentions = outputs[-1]  # Last element is attentions tuple
    last_layer_attentions = attentions[-1]  # Last layer
    
    # Average attention across all heads
    avg_attention = last_layer_attentions.mean(dim=1).squeeze().cpu().numpy()
    
    # Take the [CLS] token attention to other tokens (common approach)
    cls_attention = avg_attention[0]  # First token is [CLS]
    
    return tokens, cls_attention

# -----------------------
# Method 2: Occlusion-based importance (most reliable)
# -----------------------
def explain_with_occlusion(input_ids, attention_mask, tactic_idx):
    """Measure importance by occluding each token and measuring prediction change."""
    # Get baseline prediction
    with torch.no_grad():
        logits = model(input_ids, attention_mask)
        probs = torch.sigmoid(logits)
        baseline_prob = probs[0, tactic_idx].item()
    
    # Get tokens
    tokens = tokenizer.convert_ids_to_tokens(input_ids[0].cpu().numpy())
    
    # Occlude each non-special token and measure change
    importance_scores = []
    
    for i in range(input_ids.shape[1]):
        # Skip special tokens: [CLS], [SEP], [PAD]
        token_id = input_ids[0, i].item()
        if token_id in [tokenizer.cls_token_id, tokenizer.sep_token_id, tokenizer.pad_token_id]:
            importance_scores.append(0.0)
            continue
        
        # Create occluded input
        occluded_input = input_ids.clone()
        # Replace token with [MASK] token if available, otherwise with [UNK]
        if tokenizer.mask_token_id is not None:
            occluded_input[0, i] = tokenizer.mask_token_id
        else:
            occluded_input[0, i] = tokenizer.unk_token_id
        
        # Get prediction with occluded token
        with torch.no_grad():
            occluded_logits = model(occluded_input, attention_mask)
            occluded_probs = torch.sigmoid(occluded_logits)
            occluded_prob = occluded_probs[0, tactic_idx].item()
        
        # Importance = change in probability
        importance = abs(baseline_prob - occluded_prob)
        importance_scores.append(importance)
    
    return tokens, importance_scores

# -----------------------
# Visualization
# -----------------------
def visualize_feature_importance(feature_scores, title):
    """Create a bar chart of feature importance."""
    features = list(feature_scores.keys())
    scores = list(feature_scores.values())
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(features, scores)
    plt.title(title, fontsize=14)
    plt.xlabel('Feature', fontsize=12)
    plt.ylabel('Importance (%)', fontsize=12)
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Add value labels on bars
    for bar, score in zip(bars, scores):
        height = bar.get_height()
        if height > 0:  # Only label non-zero bars
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{score:.1f}%', ha='center', va='bottom')
    
    plt.show()

def print_top_tokens(tokens, scores, feature_map=None, n=20):
    """Print the top n most important tokens."""
    # Pair tokens with their scores
    token_scores = list(zip(tokens, scores))
    
    # Filter out special tokens and zero scores
    filtered_scores = []
    for i, (token, score) in enumerate(token_scores):
        if token not in ['[CLS]', '[SEP]', '[PAD]'] and score > 0:
            # Add feature info if available
            if feature_map and feature_map[i] is not None:
                filtered_scores.append((token, score, feature_map[i]))
            else:
                filtered_scores.append((token, score, "Unknown"))
    
    # Sort by score descending
    filtered_scores.sort(key=lambda x: x[1], reverse=True)
    
    print(f"\nTop {min(n, len(filtered_scores))} important tokens:")
    print("-" * 60)
    if filtered_scores and len(filtered_scores[0]) == 3:
        # With feature info
        print(f"{'Rank':<5} {'Token':<20} {'Score':<12} {'Feature':<10}")
        print("-" * 60)
        for i, (token, score, feature) in enumerate(filtered_scores[:n]):
            print(f"{i+1:<5} {token:<20} {score:<12.6f} {feature:<10}")
    else:
        # Without feature info
        print("-" * 50)
        for i, (token, score) in enumerate(filtered_scores[:n]):
            print(f"{i+1:2d}. {token:20s} {score:.6f}")

# -----------------------
# Run analysis on samples
# -----------------------
if __name__ == "__main__":
    # Load data
    df = pd.read_csv("scripts/supervised/datasets/enriched_with_epss_to_tactic/enriched_train_val_data.csv")
    
    # Tactics columns
    tactics_columns = [
        'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
        'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
        'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
        'Exfiltration', 'Impact'
    ]
    
    # Select 3 random samples
    sample_indices = df.sample(3, random_state=42).index.tolist()
    
    for i, sample_idx in enumerate(sample_indices):
        print(f"\n{'='*70}")
        print(f"ANALYZING SAMPLE {i+1}/{len(sample_indices)}")
        print(f"CVE: {df.iloc[sample_idx]['ID']}")
        print(f"Text preview: {df.iloc[sample_idx]['Text'][:150]}...")
        print(f"{'='*70}")
        
        # Get the row
        row = df.iloc[sample_idx]
        
        # Tokenize with feature tracking
        print("\nTokenizing with feature tracking...")
        tokens, feature_map, input_ids, attention_mask = tokenize_with_feature_spans(row)
        
        # Count tokens per feature
        feature_counts = {}
        for feat in feature_map:
            if feat is not None:
                feature_counts[feat] = feature_counts.get(feat, 0) + 1
        
        print(f"Token counts by feature: {feature_counts}")
        
        # Get actual tactics
        actual_tactics = df.iloc[sample_idx][tactics_columns]
        actual_tactic_names = [tactics_columns[j] for j, val in enumerate(actual_tactics) if val == 1]
        print(f"Actual tactics: {', '.join(actual_tactic_names)}")
        
        # Get model predictions
        probs = get_predictions(input_ids, attention_mask)
        predicted_tactics = []
        for j, prob in enumerate(probs):
            if prob > 0.5:  # Using 0.5 threshold
                predicted_tactics.append((tactics_columns[j], prob))
        
        if not predicted_tactics:
            # If no prediction above 0.5, take the highest probability
            max_idx = np.argmax(probs)
            predicted_tactics = [(tactics_columns[max_idx], probs[max_idx])]
        
        print("Model predictions:")
        for tactic_name, prob in predicted_tactics:
            print(f"  - {tactic_name}: {prob:.4f}")
        
        # Analyze each predicted tactic
        for tactic_name, prob in predicted_tactics:
            tactic_idx = tactics_columns.index(tactic_name)
            
            print(f"\n{'='*50}")
            print(f"EXPLAINING: {tactic_name} (probability: {prob:.4f})")
            print(f"{'='*50}")
            
            # Method 1: Attention-based
            print("\nMethod 1: Attention-based Analysis")
            try:
                tokens_att, scores_att = explain_with_attention(input_ids, attention_mask)
                feature_scores_att = aggregate_by_feature(feature_map, scores_att)
                print("Feature importance (%):")
                for feature, score in sorted(feature_scores_att.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {feature}: {score:.1f}%")
                
                # Print top tokens
                print_top_tokens(tokens_att, scores_att, feature_map, n=15)
            except Exception as e:
                print(f"  Attention method failed: {e}")
            
            # Method 2: Occlusion-based (most reliable)
            print("\nMethod 2: Occlusion-based Analysis (Most Reliable)")
            try:
                tokens_occ, scores_occ = explain_with_occlusion(input_ids, attention_mask, tactic_idx)
                feature_scores_occ = aggregate_by_feature(feature_map, scores_occ)
                print("Feature importance (%):")
                for feature, score in sorted(feature_scores_occ.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {feature}: {score:.1f}%")
                
                # Print top tokens
                print_top_tokens(tokens_occ, scores_occ, feature_map, n=15)
                
                # Visualize
                visualize_feature_importance(feature_scores_occ,
                                          f"Occlusion Analysis: {tactic_name} (Prob: {prob:.3f})")
                
                # Store for summary
                best_scores = feature_scores_occ
                
            except Exception as e:
                print(f"  Occlusion method failed: {e}")
                best_scores = None
            
            # Summary
            print("\n" + "="*50)
            print("SUMMARY: Most Important Features")
            print("="*50)
            
            if best_scores:
                print("\nFeature importance from occlusion method:")
                for feature, score in sorted(best_scores.items(), key=lambda x: x[1], reverse=True):
                    if score > 0:
                        print(f"  {feature}: {score:.1f}%")
                
                # Find the most important feature
                if best_scores:
                    most_important = max(best_scores.items(), key=lambda x: x[1])
                    print(f"\nMost important feature: {most_important[0]} ({most_important[1]:.1f}%)")
                    
                    # Analyze why this feature is important
                    print(f"\nWhy {most_important[0]} is important:")
                    # Show tokens from this feature with high scores
                    print("Important tokens from this feature:")
                    important_tokens = []
                    for idx, (token, score) in enumerate(zip(tokens_occ, scores_occ)):
                        if feature_map[idx] == most_important[0] and score > 0:
                            important_tokens.append((token, score))
                    
                    # Sort by score and show top 5
                    important_tokens.sort(key=lambda x: x[1], reverse=True)
                    for token, score in important_tokens[:5]:
                        print(f"  '{token}' (score: {score:.6f})")
    
    print(f"\n{'='*70}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*70}")