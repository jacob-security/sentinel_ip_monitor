import os
import sqlite3
import traceback

# Modules
from scanner import scan_network_traffic
from intel_manager import gather_intel_feodo

# Get absolute path for database
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "sentinel.db")

# Initializes the database with 2 tables: malicious_ips containing known botnet C2 ips from feodo
# and observed_traffic containing remote network connections gathered from the ss command  

def initialize_db() -> None:
    with sqlite3.connect(DB_PATH) as connection:
        try:
            print("--- Initializing Database ---\n")
            cursor = connection.cursor()

            # initialize malicious_ips database
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malicious_ips(
                    ip_address TEXT PRIMARY KEY,
                    threat_type TEXT,
                    source TEXT,
                    date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS observed_traffic(
                    remote_ip TEXT PRIMARY KEY,
                    remote_port INTEGER,
                    protocol TEXT,
                    process TEXT,
                    connection_count INTEGER DEFAULT 1,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            print("[+] Database initialized")

            connection.commit()

        except Exception as e:
            print(f"[-] Intialization failed: {e}")


# Inserts the malicious IP info into the malicious_ips table.
# Data fields are IP address, source (the API from which the threat list was gathered)
# and threat type. For Feodo, which specifically provides a threat list of botnet C2 servers
# the threat type is "botnet." The intel input from this function is provided in intel_manager.py

def populate_malicious_ips(intel: list[tuple[str,str,str,]]) -> None:
    
    query = '''
        INSERT INTO malicious_ips (ip_address, threat_type, source)
        VALUES (?, ?, ?)
        ON CONFLICT(ip_address) DO NOTHING
    '''

    with sqlite3.connect(DB_PATH) as connection:
        try:
            cursor = connection.cursor()
            cursor.executemany(query, intel)
            connection.commit()
            print(f"[+] Success: added {len(intel)} ip addresses to malicious_ips table")

        except Exception as e:
            print(f"[-] Error populating malicious_ips table")
            traceback.print_exc()

# Inserts the observed connections into the observed_traffic table
# traffic is "observed" because it stores all the connections seen 
# and keeps count of how many times they were seen. This functionality 
# could eventually be used to detect beaconing

def populate_observed_traffic(traffic: list[tuple[str, int, str, str]]) -> None:
    
    # ON CONFLICT logic increments counter which could be used to detect beaconing
    query = '''
        INSERT INTO observed_traffic (remote_ip, remote_port, protocol, process)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(remote_ip) DO UPDATE SET
            connection_count = connection_count + 1,
            last_seen = CURRENT_TIMESTAMP
    '''

    with sqlite3.connect(DB_PATH) as connection:
        try:
            cursor = connection.cursor()
            cursor.executemany(query, traffic)
            connection.commit()
            print(f"[+] Success: added {len(traffic)} ip_addresses to observed_traffic table")
        
        except Exception as e:
            print("[-] Error populating observed_traffic table")
            traceback.print_exc()

# performs an INNER JOIN on the malicious_ips and observed traffic tables
# and alerts with print statement if any matches found
def check_for_threats() -> list:

    with sqlite3.connect(DB_PATH) as connection:
        try:
            cursor = connection.cursor()
            
            # INNER JOIN logic
            query = '''
                SELECT
                    ot.remote_ip,
                    ot.remote_port,
                    ot.process,
                    mi.source
                FROM
                    observed_traffic ot
                JOIN
                    malicious_ips mi ON ot.remote_ip = mi.ip_address
            '''

            cursor.execute(query)
            hits = cursor.fetchall()
            
            # ALERT Message
            if hits:
                print(f"ALERT: {len(hits)} Malicious connections detected!")
                for ip, port, proc, desc in hits:
                    print(f"[!] MATCH: {proc} is talking to {ip}:{port} ({desc})")
            else:
                print("No malicious matches found in current traffic.")
            
            return hits
        except Exception as e:
            print(f"[-] Error in threat check {e}")
            traceback.print_exc()
# 
# def main():
#     initialize_db()
#     feodo_ips = gather_intel_feodo()
#     populate_malicious_ips(feodo_ips)
#     observed_traffic = scan_network_traffic()
#     populate_observed_traffic(observed_traffic)
#     check_for_threats()
#     
# 
# if __name__ == "__main__":
#     main()
