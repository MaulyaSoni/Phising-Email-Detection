import pickle

def predict_email(model, vectorizer, email_text):
    # Vectorize the input email
    email_vector = vectorizer.transform([email_text])

    # Make a prediction
    prediction = model.predict(email_vector)
    return "Phishing" if prediction[0] == 1 else "Not Phishing"

if __name__ == "__main__":
    # Load the model and vectorizer
    with open("models/phishing_detector.pkl", "rb") as f:
        model = pickle.load(f)
    with open("models/vectorizer.pkl", "rb") as f:
        vectorizer = pickle.load(f)

    # Dummy data for testing
    dummy_emails = [
        {"text": "Congratulations! You've won a $1,000 Walmart gift card. Click here to claim.", "label": "Phishing"},
        {"text": "Hi Bob, can you please send me the report we discussed yesterday?", "label": "Not Phishing"},
        {"text": "URGENT: Your bank account has been suspended. Please verify your details immediately.", "label": "Phishing"},
        {"text": "Let's catch up for lunch next week. Are you free on Tuesday?", "label": "Not Phishing"}
    ]

    correct_predictions = 0
    for email in dummy_emails:
        result = predict_email(model, vectorizer, email["text"])
        print(f"Email: {email['text']}")
        print(f"Prediction: {result}")
        print(f"Expected: {email['label']}")
        if result == email["label"]:
            correct_predictions += 1
        print("-"*20)
    
    accuracy = (correct_predictions / len(dummy_emails)) * 100
    print(f"Dummy Data Accuracy: {accuracy:.2f}%")