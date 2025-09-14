import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import numpy as np
import os

def train_and_evaluate_models(data_file, model_dir):
    # Load preprocessed data
    with open(data_file, "rb") as f:
        X, y, _ = pickle.load(f)

    # Convert X to a dense array if it's sparse
    if hasattr(X, "toarray"):
        X = X.toarray()

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Define models
    models = {
        "Logistic Regression": LogisticRegression(random_state=42),
        "Random Forest": RandomForestClassifier(random_state=42),
        "SVM": SVC(random_state=42)
    }

    best_accuracy = 0
    best_model = None
    best_model_name = ""

    # Train and evaluate each model
    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"{name} Accuracy: {accuracy:.2f}")

        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_model = model
            best_model_name = name

    # Save the best model
    if best_model:
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
        model_file = os.path.join(model_dir, "phishing_detector.pkl")
        with open(model_file, "wb") as f:
            pickle.dump(best_model, f)
        print(f"Best model ({best_model_name}) saved to {model_file} with accuracy: {best_accuracy:.2f}")

if __name__ == "__main__":
    train_and_evaluate_models("data/preprocessed_data.pkl", "models")
