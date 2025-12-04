from utils.colors import GREEN, YELLOW, RED, CYAN, RESET  # Import ANSI color constants for terminal output
from utils.time_utils import get_timestamp  # Import function that returns a formatted timestamp string

def format_abuseipdb_report(data):  # Define function that formats AbuseIPDB response data into a report
    if not isinstance(data, dict):  # Check if input is not a dictionary
        return "Error: Invalid AbuseIPDB response format."  # Return error message when input type is invalid

    # Normalize data whether nested or flat  # Comment explaining the normalization step
    d = data.get("data", data)  # Extract nested "data" key if present, otherwise use the original dict

    ip = d.get("ipAddress", "Unknown")  # Retrieve IP address from response or set default
    score = d.get("abuseConfidenceScore", 0)  # Retrieve abuse confidence score or default to 0
    reports = d.get("totalReports", "Unknown")  # Retrieve total number of reports or default
    last_reported = d.get("lastReportedAt", "Never")  # Retrieve last report timestamp or default to "Never"
    isp = d.get("isp", "Unknown")  # Retrieve ISP/host value or default
    domain = d.get("domain", "Unknown")  # Retrieve domain value or default

    # Risk coloring  # Comment marking the start of the risk classification section
    if score >= 70:  # Check if abuse score is 70 or higher
        risk = RED + "HIGH" + RESET  # Assign high risk label with red color
    elif score >= 30:  # Check if abuse score is 30 or higher
        risk = YELLOW + "MEDIUM" + RESET  # Assign medium risk label with yellow color
    else:  # All remaining values fall into this case
        risk = GREEN + "LOW" + RESET  # Assign low risk label with green color

    timestamp = get_timestamp()  # Generate current timestamp using utility function

    # --- GEO INTEL SECTION ---  # Comment marking the start of the geo-intel subsection
    country = d.get("countryCode", "Unknown")  # Retrieve country code or default
    region = d.get("regionName", "Unknown")  # Retrieve region name or default
    city = d.get("city")  # Retrieve city value (may be None)
    lat = d.get("latitude")  # Retrieve latitude (may be None)
    lon = d.get("longitude")  # Retrieve longitude (may be None)

    if city and city != "None":  # Check that city exists and is not the literal string "None"
        location_line = f"Location: {city}, {region} - {country}"  # Build formatted location string with city + region + country
    else:  # No valid city data available
        location_line = f"Country only: {country}"  # Build fallback string that contains country only

    coord_line = f"Approx Coordinates: {lat}, {lon}" if lat and lon else ""  # Build coordinates line if both lat/lon are present

    base = f"""  # Start multi-line formatted string for the report
{CYAN}===== ABUSEIPDB THREAT REPORT ====={RESET}  # Report header with cyan coloring
Timestamp: {timestamp}  # Insert dynamic timestamp
IP Address: {ip}  # Insert extracted IP address
{location_line}  # Insert formatted location line
{coord_line}  # Insert formatted coordinate line if available
ISP/Host: {isp}  # Insert ISP/host information
----------------------------------------  # Separator line
Risk Level: {risk}  # Insert colored risk level label
----------------------------------------  # Closing separator
"""  # End of multi-line formatted string
    return base.strip()  # Return the report string with leading/trailing whitespace removed
