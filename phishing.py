import csv
from pathlib import Path

PHISHING_KEYWORDS = [
    "urgent",
    "password",
    "click here",
    "your account",
    "blocked",
    "security",
    "win money",
    "special offer",
    "free",
    "verify",
]

DATASET_PATH = Path(__file__).resolve().parent / "data-set" / "emails.csv"


def find_indicators(text):
    if not text or not isinstance(text, str):
        return []

    normalized_text = text.casefold()
    found = []
    for keyword in PHISHING_KEYWORDS:
        if keyword.casefold() in normalized_text and keyword not in found:
            found.append(keyword)
    return found


def analyze_email(text):
    indicators = find_indicators(text)
    if not text:
        return 0.0, indicators

    score = (len(indicators) / len(PHISHING_KEYWORDS)) * 100
    return round(score, 1), indicators


def load_dataset(csv_path=DATASET_PATH):
    emails = []

    with open(csv_path, newline="", encoding="utf-8", errors="ignore") as file:
        reader = csv.DictReader(file)
        for row in reader:
            body = (row.get("text") or row.get("body") or "").strip()
            label = row.get("spam")
            emails.append({"body": body, "label": label})

    return emails


def detect_phishing_in_dataset(csv_path=DATASET_PATH):
    results = []

    for index, email in enumerate(load_dataset(csv_path), start=1):
        body = email["body"]
        score, indicators = analyze_email(body)
        is_phishing = bool(indicators) and score >= 25

        results.append(
            {
                "index": index,
                "score": score,
                "indicators": indicators,
                "is_phishing": is_phishing,
                "label": email.get("label"),
            }
        )

    return results


if __name__ == "__main__":
    dataset = load_dataset()
    results = detect_phishing_in_dataset()

    print(f"Loaded {len(dataset)} emails from {DATASET_PATH}")
    print(f"Detected phishing-like messages: {sum(1 for result in results if result['is_phishing'])}/{len(results)}")

    for result in results[:5]:
        print(f"Email {result['index']}: suspicion score {result['score']}%")
        print(f"Indicators: {', '.join(result['indicators']) if result['indicators'] else 'none'}")
        if result["is_phishing"]:
            print("⚠️ This message looks suspicious (potential phishing).")
        else:
            print("✅ This message does not appear to be dangerous.")
        print("-" * 40)
