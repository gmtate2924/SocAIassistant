import os   # Import OS module to read environment variables
from dotenv import load_dotenv  # Import dotenv to load .env file into environment
load_dotenv()  # Load environment variables from .env file
import socket  # Import socket module for IP validation and DNS resolution
import shodan  # Import Shodan API client library
import requests  # Import HTTP client for fallback API enrichment if needed
from rich.console import Console  # Import Console for rich terminal printing
from rich.panel import Panel  # Import Panel for boxed output formatting

console = Console()  # Create a Rich console instance for terminal output

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "").strip() or None  # Load Shodan API key from OS env and sanitize it

def resolve_target(target):  # Define helper function to detect IP or resolve domains
    """  # Begin docstring
    Attempt to determine if target is IP or domain.  # Explain purpose
    If domain, resolve to IP for SOC host enrichment.  # Explain primary SOC use
    """  # End docstring
    try:  # Attempt IPv4 validation
        socket.inet_aton(target)  # Validate if it's an IPv4 address
        return target  # Return IP directly if valid
    except:  # IPv4 validation failed
        try:  # Try domain to IP DNS resolution
            return socket.gethostbyname(target)  # Resolve domain name to IPv4
        except:  # DNS resolution failed
            return None  # Return None if resolution fails

def lookup_shodan(target):  # Define simplified Shodan enrichment lookup function
    """  # Begin docstring
    Simplified Shodan SOC enrichment, preserving only critical host intel.  # Explain SOC intent
    """  # End docstring

    if not SHODAN_KEY:  # Check if API key is missing
        return {"error": "SHODAN_API_KEY missing"}  # Return error dict if missing

    ip = resolve_target(target)  # Resolve domain or validate IP
    if not ip:  # If resolution failed
        return {"error": f"Cannot resolve: {target}"}  # Return error dict

    client = shodan.Shodan(SHODAN_KEY)  # Create Shodan API client instance

    try:  # Begin protected lookup block
        data = client.host(ip)  # Query Shodan for host data

        simple = {  # Construct simplified SOC enrichment dict
            "investigated_target": target,  # Store original target analyst submitted
            "resolved_ip": ip,  # Store resolved or validated IP
            "org_owner": data.get("org", "Unknown"),  # Store org owner or fallback
            "isp": data.get("isp", "Unknown"),  # Store ISP or fallback
            "country": data.get("country_name", "Unknown"),  # Store country or fallback
            "open_ports": data.get("ports", []),  # Get open ports or fallback to empty
            "hostnames": data.get("hostnames", []),  # Get hostnames or fallback
            "os": data.get("os", "Not detected"),  # OS enrichment or fallback
            "last_update": data.get("last_update", "Unknown"),  # Last host intel update or fallback
        }  # End dict

        if "latitude" in data and "longitude" in data:  # If Geo coordinates exist
            simple["geo_location"] = f"{data['latitude']}, {data['longitude']}"  # Format and insert coordinates

        vulns = data.get("vulns", {})  # Extract vuln data safely
        if isinstance(vulns, dict):  # Ensure it's a dict
            simple["vulnerabilities"] = list(vulns.keys())  # Convert CVE keys to list

        return simple  # Return finalized enrichment summary dict

    except shodan.APIError as e:  # Catch Shodan API errors
        return {"error": f"Shodan API error: {e}"}  # Return error dict

def format_shodan_panel(data):  # Define optional UI print helper
    """  # Begin docstring
    Print Shodan enrichment into rich panel without modifying core enrichment behavior.  # SOC intent
    """  # End docstring
    if not data or "error" in data:  # If data empty or error key present
        console.print(Panel(str(data.get("error", "Unknown failure")), border_style="red", title="Shodan Enrichment"))  # Print error panel
    else:  # If valid data
        console.print(Panel(str(data), border_style="cyan", title="Shodan Threat Intel"))  # Print data panel

# free trial end: Nov26th 
