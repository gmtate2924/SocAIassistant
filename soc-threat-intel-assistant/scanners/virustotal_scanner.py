import os  # Import OS module for environment variable access
import time  # Import time module for sleep/polling delays
import requests  # Import requests library for HTTP API calls
import base64  # Import base64 module for decoding analysis IDs

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # Load VirusTotal API key from environment variable
VT_ANALYSIS = "https://www.virustotal.com/api/v3/analyses/"  # Define base URL for Analysis polling endpoint

def lookup_vt_hash(hash_value):  # Define function to look up a hash on VirusTotal
    """Lookup a SHA-256 hash on VirusTotal without file operations."""  # Describe function purpose
    if not VT_KEY:  # Check if API key was not loaded
        return {"error": "VirusTotal API key missing"}  # Return error dictionary when key is missing

    headers = {"x-apikey": VT_KEY}  # Construct request headers with API key

    # Try 1: direct enrichment lookup  # Label for lookup attempt section
    try:  # Start API lookup attempt
        r = requests.get("https://www.virustotal.com/api/v3/files/" + hash_value, headers=headers, timeout=10)  # Perform hash enrichment lookup via REST API
        if r.status_code == 200:  # Check if API returned success
            stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})  # Extract latest analysis stats from JSON response
            total = sum(stats.values()) if stats else 0  # Sum all detection category values, fallback to 0
            mal = stats.get("malicious", 0)  # Extract malicious detection count or fallback to 0

            return {  # Return formatted IOC dictionary
                "indicator": hash_value,  # Include queried hash as indicator value
                "malicious": mal,  # Include malicious detection count
                "total": total,  # Include total detection count
                "type": "hash lookup"  # Label result type
            }
        else:  # API did not find hash
            return {"error": f"Hash not found ({r.status_code})"}  # Return error dictionary with HTTP status
    except Exception as e:  # Catch any request or parsing failure
        return {"error": str(e)}  # Return exception message as error string

def decode_aid(aid):  # Define function to decode a VirusTotal analysis ID safely
    """Decode a VT analysis ID safely."""  # Describe function purpose
    try:  # Start base64 decode attempt
        decoded = base64.b64decode(aid).decode()  # Decode analysis ID from base64 to UTF-8 string
        return decoded.split(":")[0]  # Return first portion of decoded string before colon
    except:  # Decode failed
        return aid  # Return original AID if decode fails

def poll_vt_analysis(aid, hash_value):  # Define function that polls an analysis result
    """Poll VirusTotal analysis until completed."""  # Describe polling function purpose
    headers = {"x-apikey": VT_KEY}  # Build request headers using API key
    analysis_id = decode_aid(aid)  # Decode AID to raw analysis ID with helper function

    for _ in range(60):  # Loop polling up to 60 times
        try:  # Start polling API call attempt
            r = requests.get(VT_ANALYSIS + analysis_id, headers=headers, timeout=5)  # Request analysis result from VirusTotal
            if r.status_code == 200:  # Check if polling call returned success
                attrs = r.json()["data"]["attributes"]  # Extract attributes object from response JSON
                if attrs.get("status") == "completed":  # Check if analysis is marked completed
                    stats = attrs.get("stats", {})  # Extract stats dictionary
                    total = sum(stats.values())  # Sum all detection stat values
                    mal = stats.get("malicious", 0)  # Extract malicious stat or default to 0

                    return {  # Return formatted result once analysis completes
                        "indicator": hash_value,  # Include original hash indicator
                        "malicious": mal,  # Include malicious detection count
                        "total": total,  # Include total detection count
                        "type": "hash lookup"  # Maintain type label
                    }
        except:  # API call or JSON parse failed
            pass  # Silently skip errors while polling
        time.sleep(1)  # Wait 1 second before next poll attempt

    return {"error": "Analysis polling timed out"}  # Return timeout error after polling ends
