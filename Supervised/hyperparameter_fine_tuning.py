import optuna
import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModel, get_linear_schedule_with_warmup

##############################################
# Configuration
##############################################

class Config:
    TRAIN_CSV = "scripts/supervised/datasets/enriched_with_epss_to_tactic/enriched_train_val_data.csv"
    VAL_CSV = "scripts/supervised/datasets/enriched_with_epss_to_tactic/enriched_train_val_data.csv"
    
    MODEL_NAME = "jackaduma/SecRoBERTa"
    NUM_LABELS = 14        # Set to the number of tactic labels (columns 6 onward)
    MAX_LENGTH = 320
    DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


##############################################
# Dataset Definition
##############################################

class TransformerDataset(Dataset):
    def __init__(self, dataframe):
        self.data = dataframe
        # Use the "Text" column as the input text.
        self.texts = dataframe["Text"].tolist()
        # Use all columns from the 6th column onward as labels.
        self.labels = dataframe.iloc[:, 6:].values.astype("float32")
        self.tokenizer = AutoTokenizer.from_pretrained(Config.MODEL_NAME)
        self.max_length = Config.MAX_LENGTH
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = self.texts[idx]
        encoding = self.tokenizer.encode_plus(
            text,
            add_special_tokens=True,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_attention_mask=True,
            return_tensors="pt"
        )

        item = {key: val.squeeze() for key, val in encoding.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item


##############################################
# Model Definition
##############################################

class SecRoBERTaModel(nn.Module):
    def __init__(self, dropout_rate):
        super(SecRoBERTaModel, self).__init__()
        self.transformer = AutoModel.from_pretrained(Config.MODEL_NAME)
        self.dropout = nn.Dropout(dropout_rate)
        hidden_size = self.transformer.config.hidden_size
        self.output = nn.Linear(hidden_size, Config.NUM_LABELS)
    
    def forward(self, input_ids, attention_mask):
        outputs = self.transformer(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs[1]
        x = self.dropout(pooled_output)
        logits = self.output(x)
        return logits


##############################################
# Evaluation Function
##############################################

def evaluate(model, dataloader, criterion):
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(Config.DEVICE)
            attention_mask = batch["attention_mask"].to(Config.DEVICE)
            labels = batch["labels"].to(Config.DEVICE)
            
            logits = model(input_ids, attention_mask)
            loss = criterion(logits, labels)
            total_loss += loss.item()
            
            probs = torch.sigmoid(logits)
            preds = (probs > 0.5).float()
            all_preds.append(preds.cpu())
            all_labels.append(labels.cpu())
    
    avg_loss = total_loss / len(dataloader)
    all_preds = torch.cat(all_preds)
    all_labels = torch.cat(all_labels)
    accuracy = (all_preds == all_labels).float().mean().item()
    return avg_loss, accuracy


##############################################
# Objective Function for Optuna
##############################################

def objective(trial):
    # Hyperparameter suggestions
    lr = trial.suggest_float("lr", 1e-5, 5e-5, log=True)
    dropout_rate = trial.suggest_float("dropout_rate", 0.1, 0.5)
    batch_size = trial.suggest_categorical("batch_size", [16, 32])
    epochs = trial.suggest_int("epochs", 2, 5)
    
    # Load data 
    train_df = pd.read_csv(Config.TRAIN_CSV)
    val_df = pd.read_csv(Config.VAL_CSV)
    
    train_dataset = TransformerDataset(train_df)
    val_dataset = TransformerDataset(val_df)
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    
    # Create model with chosen hyperparameters
    model = SecRoBERTaModel(dropout_rate)
    model.to(Config.DEVICE)
    
    criterion = nn.BCEWithLogitsLoss()
    optimizer = optim.AdamW(model.parameters(), lr=lr)
    
    total_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=total_steps)
    
    # Training loop
    for epoch in range(epochs):
        model.train()
        total_train_loss = 0
        
        for batch in train_loader:
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(Config.DEVICE)
            attention_mask = batch["attention_mask"].to(Config.DEVICE)
            labels = batch["labels"].to(Config.DEVICE)
            
            logits = model(input_ids, attention_mask)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()
            scheduler.step()
            total_train_loss += loss.item()
        
        avg_train_loss = total_train_loss / len(train_loader)
        print(f"Epoch {epoch+1}/{epochs} - Train Loss: {avg_train_loss:.4f}")
    
    # Evaluate on validation set
    val_loss, val_accuracy = evaluate(model, val_loader, criterion)
    print(f"Trial {trial.number}: lr={lr:.1e}, dropout_rate={dropout_rate:.2f}, batch_size={batch_size}, epochs={epochs}, val_accuracy={val_accuracy:.4f}")
    return val_accuracy


##############################################
# Run Optuna
##############################################

if __name__ == "__main__":
    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=10)
    
    print("Best trial:")
    best_trial = study.best_trial
    print(f"  Value (Val Accuracy): {best_trial.value:.4f}")
    for key, value in best_trial.params.items():
        print(f"  {key}: {value}")
