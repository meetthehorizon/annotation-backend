import csv
import sys
import os
from pathlib import Path

# Add the backend directory to Python path
backend_dir = str(Path(__file__).parent)
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from app import create_app
from app.extensions import db

# Use the correct import based on where your Concept model is defined
try:
    from app.models import Concept  # Try this first
except ImportError:
    from models import Concept  # Fallback to this if the above fails


def load_concepts(csv_path):
    app = create_app()
    with app.app_context():
        with open(csv_path, mode="r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Skip if concept already exists
                if Concept.query.filter_by(concept_label=row["concept_label"]).first():
                    continue

                concept = Concept(
                    concept_label=row["concept_label"],
                    hindi_label=row.get("hindi_label", ""),
                    sanskrit_label=row.get("sanskrit_label", ""),
                    english_label=row.get("english_label", ""),
                    mrsc=row.get("mrsc", ""),
                )
                db.session.add(concept)

            db.session.commit()
            print(f"Successfully loaded concepts from {csv_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python load_concepts_from_csv.py <path_to_csv>")
        sys.exit(1)

    load_concepts(sys.argv[1])
