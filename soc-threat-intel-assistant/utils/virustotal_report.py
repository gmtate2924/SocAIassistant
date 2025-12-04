from rich.panel import Panel  # Import Panel class for styled boxes
from rich.console import Console  # Import Console class for terminal rendering

console = Console()  # Create a console instance for output

def format_virustotal_report(data):  # Define function to format VirusTotal data
    """Show simple VT results for SOC analysts."""  # Docstring describing function purpose
    if not data:  # Check if data is empty or None
        return "[yellow]No data[/yellow]"  # Return colored message when no data exists

    if "error" in data:  # Check if error key exists in dictionary
        return Panel(f"{data['error']}", border_style="red", title="VirusTotal")  # Return error in a red panel
    t = data.get("type")  # Retrieve type key safely from dictionary

    if t == "hash lookup":  # Check if report type is hash lookup
        return Panel(  # Return a Rich panel for hash lookup
            f"Hash: {data['indicator']}\n"  # Insert hash indicator into string
            f"Detections: {data['malicious']}/{data['total']}",  # Insert detection ratio into string
            border_style="green",  # Use green border for this panel
            title="VirusTotal Hash Report"  # Set panel title
        )

    if t == "url scan":  # Check if report type is URL scan
        return Panel(  # Return a Rich panel for URL scan
            f"URL submitted for scanning:\n{data['indicator']}",  # Insert scanned URL indicator
            border_style="cyan",  # Use cyan border for this panel
            title="VirusTotal URL Scan"  # Set panel title
        )

    if t == "ip enrichment":  # Check if report type is IP enrichment
        return Panel(  # Return a Rich panel for IP enrichment data
            f"Target: {data['indicator']}\n"  # Insert IO C indicator IP/hostname/etc.
            f"Resolved IP: {data['resolved_ip']}\n"  # Insert resolved IP
            f"Owner Org: {data['owner_org']}\n"  # Insert owning organization
            f"Country: {data['country']}\n"  # Insert country field
            f"Malicious Detections: {data['detections']}",  # Insert malicious detection count
            border_style="magenta",  # Use magenta border for this panel
            title="VirusTotal IP Enrichment"  # Set panel title
        )
    return Panel(str(data), border_style="white", title="VirusTotal Threat Intel")  # Fallback panel for unknown types
