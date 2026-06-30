from pathlib import Path
import analyzer
import assess
import json
import argparse

from report import generate_report

def load_config(filepath):
     try:
          with open(filepath,"r") as file:
               return json.load(file)
     except FileNotFoundError:
          print(f"Error: config.json not found")
          exit(1)
     except json.JSONDecodeError:
          print("Error: config file corrupted")
          exit(1)


if __name__ == "__main__":
     parser = argparse.ArgumentParser(prog="Threatprofile",description="A command-line tool built in python to analyze network traffic from .pcap files and flag suspicious behavior. Built entirely with Scapy")
     parser.add_argument("filename",type=str)
     args = parser.parse_args()
     CONFIG_PATH = Path(__file__).parent / "config.json"
     data_ip = {"IPs":{}}
     threat_ip = {}
     pcap_path = Path(args.filename).resolve()
     pcap_filename_only = pcap_path.name
     config = load_config(CONFIG_PATH)

     try:
          print(f"Analyzing file {args.filename}...")
          analyzer.analyze_pcap_file(str(pcap_path),data_ip)
     except FileNotFoundError:
          print(f"Error:file {args.filename} not found.")
          exit(1)

     except Exception as e:
          print(f"Error: {e}")
          exit(1)
     
     print("Analysis is done.\n")
     print("Starting threat profiling...")
     
     try:
          for ip_adr in data_ip["IPs"]:
               assess.assess_all(data_ip,ip_adr,config,threat_ip)
     except Exception as e:
          print(f"Error: {e}")
          exit(1)
     print("Threat profiling done.\n")

     print("Requesting ip calls abuseipdb...\n")
     
     try:
          for ip in threat_ip:
               if any(threat_ip[ip]["is_flagged"].values()):
                    assess.check_abuseipdb(ip,config["abuseipdb_api_key"],threat_ip)
     except KeyError:
          print("Warrning: API key may be missing.")
          threat_ip[ip]["error"] = "Error: api key missing"


     report_name = generate_report(data_ip,threat_ip,pcap_filename_only)

     with open(report_name,"r") as report:
          print(report.read())
               
     

     
