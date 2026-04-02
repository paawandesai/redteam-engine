"""Export Pydantic model JSON schemas to datasets/schema/."""

import json
from pathlib import Path

from redteam.models.prompts import AdversarialPrompt
from redteam.models.results import ScanResult

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "datasets" / "schema"


def main() -> None:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)

    prompt_schema = AdversarialPrompt.model_json_schema()
    result_schema = ScanResult.model_json_schema()

    prompt_path = SCHEMA_DIR / "prompt.schema.json"
    result_path = SCHEMA_DIR / "result.schema.json"

    prompt_path.write_text(json.dumps(prompt_schema, indent=2) + "\n")
    result_path.write_text(json.dumps(result_schema, indent=2) + "\n")

    print(f"Exported {prompt_path}")
    print(f"Exported {result_path}")


if __name__ == "__main__":
    main()
