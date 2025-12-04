import json

def pretty_print(data):
    """Safely pretty-prints JSON or dict objects."""
    try:
        if isinstance(data, dict):
            print(json.dumps(data, indent=4))
        else:
            print(data)
    except Exception as e:
        print("Error formatting output:", e)
