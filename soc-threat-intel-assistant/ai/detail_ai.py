import os  # Import OS module for environment variable access
import json  # Import JSON library for encoding request payloads
import requests  # Import requests library to make HTTP API calls

API_KEY = os.getenv("OPENAI_API_KEY")  # Load OpenAI API key from environment variables

def ask_ai_about_detail(detail, category):  # Define function that asks AI to explain one SOC detail
    """Ask OpenAI to explain ONE SOC detail only."""  # Docstring explaining function purpose
    url = "https://api.openai.com/v1/responses"  # Set OpenAI API endpoint URL
    headers = {  # Begin building request headers dictionary
        "Content-Type": "application/json",  # Specify payload type is JSON
        "Authorization": f"Bearer {API_KEY}",  # Authenticate using API key
    }  # End headers dictionary

    prompt = f"""You are a professional SOC analyst assistant.  # Start prompt definition (multi-line string)
Explain ONLY this single detail below. Do not repeat the menu or add extra sections.  # Instruction for focused response

Category: {category}  # Inject category into prompt
Detail: {detail}  # Inject detail into prompt

Respond with:  # Define SOC response structure
- Context  # Request context explanation
- Why it matters  # Request importance reasoning
- Impact  # Request potential security impact
- Recommended SOC actions  # Request SOC analyst action recommendations
"""  # End multi-line prompt string

    data = {"model": "gpt-4.1-mini", "input": prompt}  # Build OpenAI request payload specifying model and prompt

    try:  # Begin protected API call attempt
        r = requests.post(url, headers=headers, data=json.dumps(data))  # Perform POST request to OpenAI API with JSON body
        if r.status_code != 200:  # Check if API response is not successful
            return "AI error: " + r.text  # Return error message with raw response text
        return r.json()["output"][0]["content"][0]["text"]  # Extract and return model output text from response JSON
    except Exception as e:  # Catch any network or parsing exceptions
        return "AI exception: " + str(e)  # Return exception message as error string

