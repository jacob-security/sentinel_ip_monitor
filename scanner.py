import subprocess
import jc
from typing import Dict, Any

# runs ss command showing active connections, parses them into a json strings using jc

def scan_network_traffic() -> list[tuple[str, int, str, str]]:
    output_ss = subprocess.run(['ss', '-tupn'], capture_output=True, text=True)
    
    if not output_ss.stdout.strip():
        return []

    data = jc.parse('ss', output_ss.stdout)
    
    network_traffic = [
            (connection.get('peer_address'), 
             connection.get('peer_port'),
             connection.get('netid'),
             get_process_string(connection))

            for connection in data
    ]

    return network_traffic

# Helper function to extract process string
def get_process_string(connection: Dict[str, Any]) -> str:
    
    process_data = connection.get('process')
    
    if not process_data or not isinstance(process_data, dict):
        return "Unknown"

    pid = list(process_data.get("process_id").keys())[0]
    user = process_data.get('process_id')[pid]['user']
    process_string = f"{user} (PID: {pid})"
    return process_string

# def main():
#     scan_network_traffic()
#     #print(scan_network_traffic())
# 
# if __name__== "__main__":
#     main()
