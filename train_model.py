import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from joblib import dump
import matplotlib.pyplot as plt

print("[INFO] Loading dataset...")
data = pd.read_csv("nsl_kdd_sample.csv")
print("[INFO] Dataset loaded. Processing...")

# ===========================
# ✅ Add Better Feature Engineering
# ===========================
data["has_payload"] = data["pkt_size"] > 0

# Create feature: count of protocols used in a packet
data["proto_count"] = data[["is_tcp", "is_udp", "is_icmp"]].sum(axis=1)

# ===========================
# ✅ Label encode: normal -> 0, attack -> 1
# ===========================
X = data.drop("label", axis=1)
y = data["label"]

le = LabelEncoder()
y_encoded = le.fit_transform(y)

# ===========================
# ✅ Split the dataset
# ===========================
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

# ===========================
# ✅ Train the Model
# ===========================
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)
importances = clf.feature_importances_
feature_names = X.columns

print("=== Feature Importances ===")
for feature, importance in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True):
    print(f"{feature}: {importance:.4f}")

plt.figure(figsize=(8,5))
plt.barh(feature_names, importances)
plt.xlabel("Feature Importance")
plt.title("Random Forest - Feature Importances")
plt.tight_layout()
plt.savefig("feature_importance.png")
plt.show()

# ===========================
# ✅ Evaluation Metrics
# ===========================
y_pred = clf.predict(X_test)
print("=== Classification Report ===")
print(classification_report(y_test, y_pred))
print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

# ===========================
# ✅ Save Model
# ===========================
dump(clf, "ids_model.pkl")
print("[SUCCESS] Improved model saved as 'ids_model.pkl'")