import pandas as pd

"""train_val_data (training_validation) should contain 80% of full data, test_data should contain 20%."""

"""
full_dataset = "scripts/supervised/datasets/enriched_to_tactic/enriched_full_data.csv"
train_val_dataset = "scripts/supervised/datasets/enriched_to_tactic/enriched_train_val_data.csv"
test_dataset = "scripts/supervised/datasets/enriched_to_tactic/enriched_test_data.csv"
"""
"""
full_dataset = "scripts/supervised/datasets/enriched_simple_cwe_to_tactic/enriched_full_data.csv"
train_val_dataset = "scripts/supervised/datasets/enriched_simple_cwe_to_tactic/enriched_train_val_data.csv"
test_dataset = "scripts/supervised/datasets/enriched_simple_cwe_to_tactic/enriched_test_data.csv"
"""
full_dataset = "scripts/supervised/datasets/enriched_with_capec_tactic/enriched_full_data.csv"
train_val_dataset = "scripts/supervised/datasets/enriched_with_capec_tactic/enriched_train_val_data.csv"
test_dataset = "scripts/supervised/datasets/enriched_with_capec_tactic/enriched_test_data.csv"

full_df = pd.read_csv(full_dataset)
full_df_size = len(full_df.index)
train_val_size = (full_df_size//10)*8
test_size = (full_df_size//10)*2

print(f"Full DF Size: {full_df_size}")
print(f"Train Val DF Size: {train_val_size}")
print(f"Test DF Size: {test_size}")

train_val_df = full_df.iloc[0:train_val_size]
test_df = full_df.iloc[train_val_size:]

train_val_df.to_csv(train_val_dataset, index=False)
test_df.to_csv(test_dataset, index=False)

print("Completed Splitting of Full Dataset into Training/validation and Test Datasets")