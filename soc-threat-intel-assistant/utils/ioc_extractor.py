import re  # Import regex module for pattern matching
from urllib.parse import urlparse  # Import URL parser to extract components from URLs

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # Regex pattern for matching IPv4 addresses
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"  # Regex pattern for matching domain names
EMAIL_REGEX = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"  # Regex pattern for matching email addresses
URL_REGEX = r"\bhttps?://[^\s]+"  # Regex pattern for matching HTTP/HTTPS URLs
SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"  # Regex pattern for matching SHA-256 hashes
FILEPATH_REGEX = r"\b[a-zA-Z]:\\[^\s]+\b|\b/[\w./-]+\b"  # Regex pattern for Windows and Unix file paths

def extract_iocs(text: str):  # Define function to extract IOCs from input text
    """ Extract possible indicators of compromise from pasted log text """  # Docstring explaining function purpose
    indicators = {  # Initialize dictionary to hold extracted indicators
        "ips": [],  # List to store detected IPs
        "domains": [],  # List to store detected domains
        "emails": [],  # List to store detected emails
        "urls": [],  # List to store detected URLs
        "sha256": [],  # List to store detected SHA-256 hashes
        "filepaths": [],  # List to store detected file paths
        "parsed_hosts_from_urls": []  # List to store parsed hostnames from URLs
    }

    indicators["ips"] = re.findall(IP_REGEX, text)  # Extract all potential IP addresses
    indicators["domains"] = re.findall(DOMAIN_REGEX, text)  # Extract all potential domains
    indicators["emails"] = re.findall(EMAIL_REGEX, text)  # Extract all potential emails
    indicators["urls"] = re.findall(URL_REGEX, text)  # Extract all potential URLs
    indicators["sha256"] = re.findall(SHA256_REGEX, text)  # Extract all potential SHA-256 hashes
    indicators["filepaths"] = re.findall(FILEPATH_REGEX, text)  # Extract all potential file paths

    valid_ips = []  # Initialize list for validated IP addresses
    for ip in indicators["ips"]:  # Iterate over extracted IPs
        octets = ip.split(".")  # Split IP into four octets
        if all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):  # Validate each octet is 0-255
            valid_ips.append(ip)  # Collect valid IP address
    indicators["ips"] = valid_ips  # Replace raw IP list with validated IP list

    for url in indicators["urls"]:  # Iterate over extracted URLs
        try:  # Attempt parsing URL safely
            parsed = urlparse(url)  # Parse the URL into components
            host = parsed.hostname  # Extract hostname from parsed URL
            if host:  # Ensure hostname exists
                indicators["parsed_hosts_from_urls"].append(host)  # Collect extracted host
        except:  # Handle any parsing exception
            continue  # Skip invalid URL and continue loop
    # Begin deduplication section by IOC category  # Comment for section purpose
    for key in ["ips", "domains", "emails", "urls", "sha256", "filepaths", "parsed_hosts_from_urls"]:  # Loop over indicator types
        seen = []  # List to track unique items
        for item in indicators.get(key, []):  # Iterate over each indicator list
            if item not in seen:  # Check if item is not already recorded
                seen.append(item)  # Record unique item
        indicators[key] = seen  # Overwrite list with deduplicated unique list

    return indicators  # Return dictionary containing all extracted & cleaned indicators
