import os  # Import module for environment variable access
import requests  # Import HTTP request client for API calls
from rich.console import Console  # Import Rich console for terminal output
from rich.panel import Panel  # Import Rich panel for formatted boxed output

console = Console()  # Create Rich console instance

OPENAI_URL = "https://api.openai.com/v1/chat/completions"  # Define OpenAI chat completions endpoint URL

def summarize_text(log_text):  # Define function that summarizes security logs/events
    """  # Begin docstring
    Produces a clean, minimal SOC-style AI summary for security events/logs.  # Describe intended output format
    Preserves:  # List assumptions of what summary should keep
    - investigation intent  # Preserve investigation purpose in summary
    - threat context  # Preserve threat context
    - analyst readability  # Preserve readability
    """  # End docstring

    key = os.getenv("OPENAI_API_KEY")  # Load OpenAI API key from OS environment
    if not key:  # Check if API key is missing
        return {"error": "OPENAI_API_KEY missing in .env"}  # Return error dict if missing

    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}  # Build request headers for API auth and JSON
    payload = {  # Start payload dict construction
        "model": "gpt-4.1-mini",  # Select summary model
        "temperature": 0.1,  # Set deterministic concise output
        "messages": [  # Begin chat messages list definition
            {"role": "system", "content": "You summarize security events for SOC analysts in a clear, minimal, low-noise format."},  # Set system instruction for summary
            {"role": "user", "content": f"Summarize this security event/log. Keep it extremely concise and focus only on the threat, source, impact, and recommended SOC action:\n\n{log_text}"}  # Insert user log text into prompt for summary
        ]  # End messages list
    }  # End payload dict

    try:  # Begin protected API call block
        r = requests.post(OPENAI_URL, headers=headers, json=payload, timeout=15)  # Execute POST request to OpenAI API
        if r.status_code == 200:  # Check if success
            text = r.json()["choices"][0]["message"]["content"]  # Extract summary text from response
            # Return minimal structured summary  # Comment describing next return block
            return {"summary": text, "type": "ai summary"}  # Return structured summary
        return {"error": f"OpenAI API returned {r.status_code}"}  # Return error if not successful
    except Exception as e:  # Catch request/parse errors
        return {"error": str(e)}  # Return exception message inside error dict
