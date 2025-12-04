from datetime import datetime, timezone

def get_timestamp():
    """Return a clean UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
