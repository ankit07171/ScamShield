"""Train the baseline classifier and print held-out metrics.  Usage: python -m scripts.train_baseline"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.config import get_settings  # noqa: E402
from app.detectors.text_classifier import train_and_save  # noqa: E402

if __name__ == "__main__":
    m = train_and_save(get_settings().model_path)
    print(json.dumps(m, indent=2))
