import json

CONTEXT_FILE = "pipeline_context.json"

def save_context(data):
    with open(CONTEXT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def load_context():
    try:
        with open(CONTEXT_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}