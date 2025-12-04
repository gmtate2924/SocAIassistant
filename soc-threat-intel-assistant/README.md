SOC Threat Intelligence Assistant

Features
- IOC Collection using internal pattern matching via regex
- IP Reputation using the abuse intelligence API from AbuseIPDB
- Ownership Attribution using registration data from WHOIS
- Internet Exposure** lookups using device banners from Shodan
- File Risk Scanning usingthe malware intelligence aggregator VirusTotal
- AI Event Summarization using summaries from OpenAI
- Detailed SOC Recommendations using detailed summaries from OpenAI

Menu
1. Collect threat indicators from log text
2. Check IP reputation using AbuseIPDB
3. Return ownership information using WHOIS
4. Uncover technical exposure data using Shodan
5. Scan a downloaded file using VirusTotal
6. Receive a concise summary using OpenAI Assistant
7. Receive a detailed summary + SOC recommendations using OpenAI Assistant
8. Exit

Setup
1. Clone or extract the project folder
2. Install thw dependencies:
```powershell
pip install -r requirements.txt
