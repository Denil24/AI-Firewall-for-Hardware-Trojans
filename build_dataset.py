# build_dataset_fast.py
import os
import pandas as pd
from imblearn.over_sampling import SMOTE
from extract_features import extract_with_regex, extract_with_ast

# Root folder where all benchmarks exist
ROOT_NETLISTS = "../netlists"  # adjust if needed
FAST_MODE = True  # ✅ Set True for speed (regex only)

# ---------------------------
# Feature Extractor Wrapper
# ---------------------------
def safe_extract(filepath):
    """Choose fast (regex) or full (AST+regex) extraction."""
    try:
        if FAST_MODE:
            features = extract_with_regex(filepath)
        else:
            features = extract_with_ast(filepath)
        return features
    except Exception as e:
        print(f"[ERROR] {filepath}: {e}")
        return None

# ---------------------------
# Dataset Builder
# ---------------------------
def process_folder(folder_path, label):
    dataset = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".v"):
                filepath = os.path.join(root, file)
                features = safe_extract(filepath)
                if features:
                    dataset.append([filepath] + features + [label])
                    print(f"[OK] {file} label={label}")
    return dataset

def main():
    dataset = []

    # Scan all benchmarks
    for benchmark in os.listdir(ROOT_NETLISTS):
        bench_path = os.path.join(ROOT_NETLISTS, benchmark, benchmark, "src")

        if not os.path.exists(bench_path):
            print(f"⚠️ Skipping {benchmark}, no src folder found.")
            continue

        tjfree = os.path.join(bench_path, "TjFree")
        tjin = os.path.join(bench_path, "TjIn")

        if os.path.exists(tjfree):
            print(f"\n📂 Processing CLEAN → {tjfree}")
            dataset += process_folder(tjfree, label=0)

        if os.path.exists(tjin):
            print(f"\n📂 Processing TROJAN-INJECTED → {tjin}")
            dataset += process_folder(tjin, label=1)

    if not dataset:
        print("\n❌ No data collected. Check your paths.")
        return

    # --- Dynamically build feature column names ---
    num_features = len(dataset[0]) - 2  # exclude filename + label
    feature_cols = [f"feature_{i}" for i in range(1, num_features + 1)]
    columns = ["filename"] + feature_cols + ["label"]

    # Convert to DataFrame
    df = pd.DataFrame(dataset, columns=columns)

    # ✅ Remove useless rows (all-zero features)
    df = df[~(df[feature_cols].sum(axis=1) == 0)]
    print(f"\n🧹 After cleaning: {df.shape}")

    # ✅ Balance dataset using SMOTE
    X = df[feature_cols]
    y = df["label"]

    if len(y.unique()) == 2 and min(y.value_counts()) > 20:  # avoid oversampling tiny datasets
        sm = SMOTE(random_state=42, k_neighbors=3)
        X_res, y_res = sm.fit_resample(X, y)
        df_balanced = pd.DataFrame(X_res, columns=feature_cols)
        df_balanced["label"] = y_res
        df_balanced["filename"] = "synthetic"  # placeholder
        df = df_balanced
        print(f"\n✅ After SMOTE balancing: {df.shape}")
        print(df['label'].value_counts())
    else:
        print("\n⚠️ Skipping SMOTE (not enough samples).")

    # Save final dataset
    df.to_csv("dataset.csv", index=False)
    print("\n💾 Saved dataset → dataset.csv")
    print("Columns:", list(df.columns))

if __name__ == "__main__":
    main()
