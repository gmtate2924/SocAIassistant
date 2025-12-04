import os  # Import OS module for accessing environment variables
import requests  # Import requests module for making HTTP API calls
from functools import lru_cache  # Import LRU cache decorator for result caching

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")  # Load AbuseIPDB API key from environment vars

@lru_cache(maxsize=50)  # Apply LRU cache with a max of 50 stored results
def check_ip_abuseipdb(ip_address):  # Define function that checks IP reputation on AbuseIPDB
    """Checks IP reputation on AbuseIPDB and caches results."""  # Docstring describing function behavior

    url = "https://api.abuseipdb.com/api/v2/check"  # Set API endpoint URL for AbuseIPDB check lookup
    headers = {  # Begin constructing request headers dictionary
        "Key": ABUSEIPDB_API_KEY,  # Insert API key into headers
        "Accept": "application/json"  # Request JSON response format
    }  # End headers dict
    params = {  # Begin constructing API query parameter dict
        "ipAddress": ip_address,  # Include target IP to check
        "maxAgeInDays": "90",  # Limit results to last 90 days
        "verbose": "true"  # Request fully verbose response
    }  # End params dict
    try:  # Start protected HTTP lookup attempt
        r = requests.get(url, headers=headers, params=params)  # Execute GET request to API
        if r.status_code != 200:  # Check if response is not success HTTP 200
            return {"error": "Lookup failed", "detail": r.text}  # Return failure and raw body text
        return r.json().get("data", {})  # Return nested data block if present or empty dict
    except Exception as e:  # Catch network or decoding exceptions
        return {"error": str(e)}  # Return error message as dictionary output
