import os  # Import module for OS environment and path operations
import json  # Import module to handle JSON serialization/deserialization
import time  # Import module for time-based delays like sleep
import socket  # Import module for network address validation and socket helpers
from datetime import datetime  # Import datetime class for timestamp parsing
import whois  # Import WHOIS lookup library for domain/IP enrichment
import requests  # Import HTTP request client for API queries
from dotenv import load_dotenv  # Import function to load .env file into environment
from rich import print as rprint  # Import rich print for terminal formatting
from rich.panel import Panel  # Import panel component for boxed output in terminal
from rich.console import Console  # Import console for rich terminal rendering

load_dotenv()  # Execute dotenv load to populate OS env variables
console = Console()  # Create rich console instance for printing
last_report = None  # Initialize variable for storing last report state

def show_ip_location(report):  # Define function to parse and display geolocation
    """Display approximate physical location for an IP report object."""  # Docstring describing intent
    if not isinstance(report, dict):  # Validate input type is dictionary
        rprint("[red]No valid data to display location[/red]")  # Print error if invalid
        return  # Exit function early

    country = report.get("countryCode")  # Extract country code if present
    region = report.get("regionName") or report.get("region")  # Extract region with fallback
    city = report.get("city")  # Extract city field if present

    if city:  # If city is available in report
        rprint(f"[bold]Location:[/bold] {city}, {region} - {country}")  # Print city+region+country
    elif country:  # If only country is available
        rprint(f"[bold]Country only:[/bold] {country}")  # Print country-only message
    else:  # If no location data exists
        rprint("Location: unavailable")  # Print unavailable fallback

    lat = report.get("latitude")  # Extract latitude
    lon = report.get("longitude")  # Extract longitude
    if lat and lon:  # Ensure both coordinates exist
        rprint(f"[bold]Approx Coordinates:[/bold] {lat}, {lon}")  # Print lat/lon coordinates

    isp = report.get("isp") or report.get("ISP")  # Extract ISP or fallback key
    if isp:  # If ISP value exists
        rprint(f"[bold]ISP/Host:[/bold] {isp}")  # Print ISP/host name

def ask_ai_about_detail(detail, category):  # Define function that asks OpenAI for SOC explanation
    """AI explanation for a single SOC detail."""  # Docstring describing purpose
    prompt = f"Category: {category}\nDetail: {detail}\nExplain this for a SOC analyst."  # Construct user prompt
    key = os.getenv("OPENAI_API_KEY")  # Load OpenAI API key from environment
    if not key:  # If no key exists
        return "OpenAI API key missing"  # Return error string

    headers = {"Authorization": f"Bearer {key}"}  # Construct authorization header
    payload = {  # Construct request payload
        "model": "gpt-4.1-mini",  # Select model
        "messages": [{"role": "user", "content": prompt}],  # Pass SOC prompt to model
        "temperature": 0.2  # Set deterministic low-variance output
    }  # End payload

    try:  # Start protected HTTP request
        r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)  # Execute chat completion POST
        return r.json()["choices"][0]["message"]["content"] if r.status_code == 200 else f"AI API error {r.status_code}"  # Return SOC output or error
    except Exception as e:  # Catch any request/parse failure
        return f"AI exception: {e}"  # Return exception message

def section_header(text, color="white"):  # Define function to print stylized section headers
    console.print(Panel(f"[bold {color}]{text}[/bold {color}]", border_style=color))  # Render text inside rich panel

def do_whois_lookup(target):  # Define function for WHOIS or RDAP IP lookup
    """WHOIS enrichment for domains or IPs."""  # Docstring describing behavior
    is_ip = False  # Initialize IP detection flag

    try:  # Try detecting if IPv4
        socket.inet_aton(target)  # Validate IPv4, throws error if not valid
        is_ip = True  # Mark target as IP if valid
    except:  # If not a valid IPv4
        pass  # Continue without crashing

    if is_ip:  # If target is IP address
        lookup_target = target.strip()  # Clean whitespace
        urls = [  # Define list of RDAP WHOIS registry endpoints
            "https://rdap.arin.net/registry/ip/",  # ARIN registry
            "https://rdap.apnic.net/ip/",  # APNIC registry
            "https://rdap.db.ripe.net/ip/",  # RIPE registry
            "https://rdap.afrinic.net/ip/",  # AFRINIC registry
            "https://rdap.lacnic.net/ip/"  # LACNIC registry
        ]  # End list

        for u in urls:  # Loop through registries
            try:  # Try querying current registry
                r = requests.get(u + lookup_target, timeout=5)  # Perform GET request
                if r.status_code == 200:  # Check if success
                    return r.json()  # Return parsed WHOIS result
            except:  # On request failure
                continue  # Continue with next registry

        return {"error": "No IP WHOIS/RDAP registry responded"}  # Return error dict when none worked

    try:  # Try domain WHOIS
        lookup_target = target.strip()  # Clean whitespace
        data = whois.whois(lookup_target)  # Perform WHOIS lookup
        if not data:  # If empty response returned
            return {"error": "No domain WHOIS responded"}  # Return error dict

        def json_safe(v):  # Define helper to sanitize output
            if isinstance(v, datetime):  # Check if datetime object
                # Convert datetime to ISO string  # Comment explaining conversion
                return v.isoformat()  # Convert to ISO 8601 string
            if isinstance(v, list):  # If value is a list
                # Recursively sanitize list members  # Comment explaining recursion
                return [json_safe(i) for i in v]  # Process each element
            # Convert value to string if not null, else None  # Comment for fallback
            return str(v) if v is not None else None  # Convert to string safely

        out = {}  # Initialize output dict
        for k, v in data.items():  # Iterate through WHOIS data
            out[k] = json_safe(v)  # Sanitize each entry into output dict
        return out  # Return sanitized WHOIS result
    except Exception as e:  # Catch lookup failures
        # Return error as dictionary  # Comment explaining fallback
        return {"error": str(e)}  # Return error dict

def lookup_vt_hash(hash_value):  # Define function for VirusTotal hash lookup
    """VirusTotal lookup for SHA-256 hashes ONLY."""  # Docstring describing intent
    VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # Load API key from OS env
    if not VT_KEY:  # If key missing
        # Return error for missing API key  # Comment explaining fallback
        return {"error": "VirusTotal API key missing"}  # Return error dict

    if len(hash_value) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hash_value):  # Validate hash length and characters
        # Return error for bad hash format  # Comment explaining fallback
        return {"error": "Invalid SHA-256 hash format"}  # Return error dict

    headers = {"x-apikey": VT_KEY}  # Build VT request headers

    try:  # Try VT lookup
        r = requests.get("https://www.virustotal.com/api/v3/files/" + hash_value, headers=headers, timeout=10)  # Perform VT GET request
        if r.status_code == 200:  # If hash exists
            stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})  # Extract analysis stats safely
            total = sum(stats.values()) if stats else 0  # Sum stats or fallback to 0
            mal = stats.get("malicious", 0)  # Extract malicious count or fallback
            # Return formatted VT hash lookup result  # Comment describing block
            return {  # Construct IOC response
                "indicator": hash_value,  # Include original hash
                "malicious": mal,  # Include malicious detection count
                "total": total,  # Include total detection count
                "type": "hash lookup"  # Label type
            }
        # Return error if not 200  # Comment explaining fallback
        return {"error": f"Hash not found ({r.status_code})"}  # Return error dict
    except Exception as e:  # On failure
        # Return exception message  # Comment explaining fallback
        return {"error": str(e)}  # Return error dict

def main_menu():  # Define CLI menu render and input function
    # Print menu header  # Comment describing block
    section_header("SOC THREAT INTELLIGENCE ASSISTANT", "white")  # Render SOC title
    console.print("1. IOC Extraction from Log")  # Print option 1
    console.print("2. AbuseIPDB Reputation Check")  # Print option 2
    console.print("3. WHOIS IP Lookup")  # Print option 3
    console.print("4. VirusTotal SHA-256 Hash Lookup")  # Print option 4
    console.print("5. Event AI Recommendations")  # Print option 5
    console.print("6. AI Summary/Recommendations")  # Print option 6
    console.print("7. Exit")  # Print option 7
    # Get trimmed CLI input  # Comment explaining return
    return input("\nChoose (1–7): ").strip()  # Read user input

def run():  # Define primary runner loop
    global last_report  # Allow global state to be modified

    from scanners.abuseipdb_scanner import check_ip_abuseipdb  # Import abuse IP lookup scanner
    from scanners.shodan_scanner import lookup_shodan  # Import Shodan scanner for host enrichment
    from scanners.otx_scanner import search_otx_ioc  # Import OTX IOC scanner for enrichment
    from ai.summarizer import summarize_text  # Import AI summary generator
    from utils.ioc_extractor import extract_iocs  # Import IOC extraction helper
    from utils.abuseipdb_report import format_abuseipdb_report  # Import report formatter
    from utils.virustotal_report import format_virustotal_report  # Import report formatter

    while True:  # Start loop
        choice = main_menu()  # Display menu and read input

        if choice == "1":  # IOC extraction path
            log = input("Paste text to extract indicators:\n")  # Read log text
            section_header("===== IOC EXTRACTION =====", "blue")  # Print section header
            iocs = extract_iocs(log)  # Extract IOCs
            last_report = iocs  # Save state
            # Print formatted JSON  # Comment explaining action
            rprint(json.dumps(iocs, indent=2))  # Print JSON with indent

        elif choice == "2":  # AbuseIPDB reputation path
            ip = input("Enter IP address:\n").strip()  # Read IP
            data = check_ip_abuseipdb(ip)  # Lookup reputation
            last_report = data  # Save state
            section_header("===== ABUSEIPDB REPORT =====", "cyan")  # Print header
            rprint(format_abuseipdb_report(data))  # Print formatted report
            # Print geolocation  # Comment explaining action
            show_ip_location(data)  # Print IP location
            rprint("----------------------------------------")  # Print separator

        elif choice == "3":  # WHOIS lookup path
            target = input("Enter domain or IP:\n").strip()  # Read target
            section_header("===== WHOIS LOOKUP RESULT =====", "green")  # Print header
            data = do_whois_lookup(target)  # Lookup WHOIS
            last_report = data  # Save state
            # Print WHOIS JSON  # Comment explaining action
            rprint(json.dumps(data, indent=2))  # Print JSON
            rprint("----------------------------------------")  # Print separator

        elif choice == "4":  # VT hash lookup path
            vt_hash = input("Enter SHA-256 hash to lookup on VirusTotal:\n").strip()  # Read hash
            data = lookup_vt_hash(vt_hash)  # Lookup VT
            last_report = data  # Save state
            section_header("===== VIRUSTOTAL HASH LOOKUP RESULT =====", "red")  # Print header
            # Print hash report  # Comment explaining action
            rprint(format_virustotal_report(data))  # Print formatted
            rprint("----------------------------------------")  # Print separator
            continue  # Continue menu loop

        elif choice == "5":  # AI explanation path
            category = input("Category:\n").strip()  # Read category
            detail = input("Detail:\n")  # Read detail
            section_header("===== AI EXPLANATION =====", "white")  # Print header
            explanation = ask_ai_about_detail(detail, category)  # Ask AI
            last_report = {"analysis": explanation}  # Save state
            # Print AI explanation  # Comment explaining display
            rprint(explanation)  # Output explanation

        elif choice == "6":  # AI summary path
            log = input("Paste log/event:\n").strip()  # Read log
            section_header("===== AI SUMMARY =====", "yellow")  # Print header
            data = summarize_text(log)  # Generate summary
            last_report = data  # Save state
            # Print summary  # Comment explaining action
            rprint(data.get("summary"))  # Print summary

        elif choice == "7":  # Exit path
            # Print and break  # Comment explaining exit
            rprint("\n👋 Exiting.")  # Goodbye message
            break  # Exit loop

        else:  # If bad option
            # Print invalid option error  # Comment explaining fallback
            rprint("[red]Invalid option, try again.[/red]")  # Print error

if __name__ == "__main__":  # If script executed directly
    # Call run  # Comment explaining entrypoint
    run()  # Execute runner
