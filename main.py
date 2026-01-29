import time
from datetime import datetime

# Modules
from scanner import scan_network_traffic
from intel_manager import gather_intel_feodo
import db_manager as db

def main():
    print("--- Sentinel IP Security Monitor Starting ---")

    # Loop runs every 10 minutes until script is manually terminated in terminal
    while True:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{current_time}] Scanning for active connections...")
        
        try:
            db.initialize_db()
            traffic_data = scan_network_traffic()
        
            if traffic_data:
                db.populate_observed_traffic(traffic_data)
                malicious_traffic = gather_intel_feodo()
                
                # delay to prevent database file lock
                time.sleep(0.5)

                db.populate_malicious_ips(malicious_traffic)
                db.check_for_threats()
            else:
                print("Status: Idle. No active established connections found.")

            print("Zzz... sleeping for 10m.")
            time.sleep(600)

        except KeyboardInterrupt:
            print("\n[!] Sentinel shuting down.")
            break
            
if __name__=="__main__":
    main()



