import requests

# gathers the list of botnet C2 IP addresses from the Feodo Tracker API
# "Botnet" will serve as the malicious IP threat type

def gather_intel_feodo(source="Feodo") -> list[tuple[str, str, str]]:
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        lines = response.text.splitlines()
        return [
                (line.strip(), "Botnet", source)
                for line in lines
                if line.strip() and not line.startswith("#")
        ]

    except Exception as e:
        print(f"[-] API Error: {e}")
        return []

# def main():
#     print("--- Gathering Malicious IPs from gather_intel_feodo() ---")
#     malicious_ips = gather_intel_feodo()
#     print("--- Malicious IPs ---")
#     for ip in malicious_ips:
#         print(f"IP address: {ip[0]:<15} | Threat Type: {ip[1]:<10} | Source: {ip[2]}")
# 
# if __name__=="__main__":
#     main()
