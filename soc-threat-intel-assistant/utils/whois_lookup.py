import whois  # Import WHOIS library for domain/IP registration lookups

def whois_detail(target):  # Define function that retrieves WHOIS details for a given target
    try:  # Begin WHOIS lookup attempt inside a protected error-handling block
        return whois.whois(target)  # Perform WHOIS query and return result object/dict
    except Exception as e:  # Catch any failure during lookup
        return {"error": str(e)}  # Return error message inside a dictionary when exception occurs
