# train_model_fast.py
import time
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
    f1_score,
)
import joblib
from tqdm import tqdm

start_time = time.time()

# ----------------------------
# Load dataset
# ----------------------------
DATASET_PATH = "dataset.csv"
print("📂 Loading dataset...")
data = pd.read_csv(DATASET_PATH)
print("✅ Dataset loaded")
print("Shape:", data.shape)

# Drop non-numeric columns
non_numeric_cols = data.select_dtypes(exclude=["number"]).columns.tolist()
if non_numeric_cols:
    print(f"\n🧹 Dropping non-numeric columns: {non_numeric_cols}")
    data = data.drop(columns=non_numeric_cols)

X = data.drop("label", axis=1)
y = data["label"]

print("\nFeatures shape:", X.shape)
print("Labels distribution:\n", y.value_counts())

# ----------------------------
# Train/Test split
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# ----------------------------
# Models & Params
# ----------------------------
models = {
    "RandomForest": RandomForestClassifier(random_state=42, n_jobs=-1, class_weight="balanced"),
    "LogisticRegression": LogisticRegression(max_iter=2000, random_state=42, solver="liblinear", class_weight="balanced"),
    "GradientBoosting": GradientBoostingClassifier(random_state=42),
    "XGBoost": XGBClassifier(
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        use_label_encoder=False,
        verbosity=0,
        scale_pos_weight=(y == 0).sum() / (y == 1).sum(),
    ),
}

param_grids = {
    "RandomForest": {"n_estimators": [100], "max_depth": [None]},
    "LogisticRegression": {"C": [1], "solver": ["liblinear"]},
    "GradientBoosting": {"n_estimators": [100], "learning_rate": [0.1]},
    "XGBoost": {"n_estimators": [100], "max_depth": [3], "learning_rate": [0.1]},
}

# ----------------------------
# Training with progress bar
# ----------------------------
print("\n🔍 Training and tuning models...")
best_models = []
for name, model in tqdm(models.items(), desc="Training models"):
    try:
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        grid = GridSearchCV(
            model,
            param_grids[name],
            cv=cv,
            scoring="accuracy",
            n_jobs=-1,
            verbose=0,
        )
        grid.fit(X_train, y_train)
        print(f"{name} ✅ Best CV Acc: {grid.best_score_:.4f} | Params: {grid.best_params_}")
        best_models.append((name, grid.best_estimator_))
    except Exception as e:
        print(f"⚠️ {name} skipped: {e}")

# ----------------------------
# Ensemble Voting
# ----------------------------
print("\n🤝 Training Ensemble Voting Classifier...")
ensemble = VotingClassifier(estimators=best_models, voting="soft", n_jobs=-1)
ensemble.fit(X_train, y_train)

# ----------------------------
# Threshold Tuning
# ----------------------------
print("\n--- Threshold Tuning ---")
y_probs = ensemble.predict_proba(X_test)[:, 1]
thresholds = np.arange(0.3, 0.91, 0.05)

best_f1, best_thresh = 0, 0.5
for thresh in thresholds:
    y_pred = (y_probs >= thresh).astype(int)
    f1 = f1_score(y_test, y_pred)
    # focus on reducing false positives for class 0
    cm = confusion_matrix(y_test, y_pred)
    false_positives = cm[0][1]
    print(f"Threshold={thresh:.2f} → F1={f1:.3f}, False Positives={false_positives}")
    if f1 > best_f1 and false_positives == 0:
        best_f1, best_thresh = f1, thresh

print(f"\n✅ Best Threshold = {best_thresh:.2f} with F1={best_f1:.3f}")

# ----------------------------
# Final Evaluation
# ----------------------------
y_pred = (y_probs >= best_thresh).astype(int)
print("\n--- Final Evaluation ---")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Save confusion matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=[0, 1], yticklabels=[0, 1])
plt.title(f"Confusion Matrix (Best Threshold={best_thresh:.2f})")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.savefig("confusion_matrix.png")
plt.close()
print("📊 Confusion matrix saved as confusion_matrix.png")

# ----------------------------
# Curves (Precision-Recall + ROC)
# ----------------------------
precisions, recalls, thresh = precision_recall_curve(y_test, y_probs)
plt.figure(figsize=(6, 5))
plt.plot(thresh, precisions[:-1], "b--", label="Precision")
plt.plot(thresh, recalls[:-1], "g-", label="Recall")
plt.axvline(best_thresh, color="red", linestyle="--", label=f"Best Thresh={best_thresh:.2f}")
plt.xlabel("Threshold")
plt.ylabel("Score")
plt.legend()
plt.title("Precision-Recall vs Threshold")
plt.savefig("precision_recall_curve.png")
plt.close()
print("📈 Precision-Recall curve saved as precision_recall_curve.png")

fpr, tpr, _ = roc_curve(y_test, y_probs)
roc_auc = auc(fpr, tpr)
plt.figure(figsize=(6, 5))
plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}")
plt.plot([0, 1], [0, 1], linestyle="--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve")
plt.legend(loc="lower right")
plt.savefig("roc_curve.png")
plt.close()
print("📈 ROC curve saved as roc_curve.png")

# ----------------------------
# Save Model
# ----------------------------
joblib.dump((ensemble, best_thresh), "trojan_detector.pkl")
print("\n💾 Model + Tuned Threshold saved as trojan_detector.pkl")

end_time = time.time()
print(f"\n⏱️ Training completed in {end_time - start_time:.2f} seconds")
