import subprocess
import os
import shutil
import json
import xml.etree.ElementTree as ET
from Wappalyzer import Wappalyzer, WebPage
from urllib.error import HTTPError

class ScanManager:
    """
    Wrapper class for external security tools (Subfinder, Nmap, etc.).
    Handles subprocess execution and output file management.
    """

    def __init__(self, output_dir="scans"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Initialize Wappalyzer
        try:
            self.wappalyzer = Wappalyzer.latest()
        except:
            # Fallback or retry logic could go here
            self.wappalyzer = Wappalyzer.latest()

    def _run_command(self, command):
        """
        Helper to run shell commands safely.
        """
        try:
            print(f"[*] Running command: {command}")
            # check=True raises CalledProcessError if return code != 0
            # text=True returns stdout/stderr as strings
            result = subprocess.run(
                command, 
                shell=True, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[!] Command failed: {e.stderr}")
            raise Exception(f"Tool execution failed: {e.stderr}")

    def run_subfinder(self, target):
        """
        Runs subfinder on the target domain.
        Command: subfinder -d target.com -o output.txt
        """
        output_file = os.path.join(self.output_dir, f"{target}_subdomains.txt")
        
        # Verify subfinder is installed
        if not shutil.which("subfinder"):
            raise Exception("Subfinder tool not found in system PATH.")

        # Construct command
        # -d: domain
        # -o: output file
        # -silent: show only subdomains in stdout (optional, but good for parsing)
        # Using list format for shell=False to prevent injection
        command = ["subfinder", "-d", target, "-o", output_file]
        
        # We need to handle the fact that _run_command expects a string or list
        # We will modify _run_command to handle list or keep shell=False
        
        print(f"[*] Running command: {' '.join(command)}")
        try:
            result = subprocess.run(
                command, 
                shell=False, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
        except subprocess.CalledProcessError as e:
            print(f"[!] Command failed: {e.stderr}")
            raise Exception(f"Tool execution failed: {e.stderr}")
            
        # Read and return results
        subdomains = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f.readlines() if line.strip()]
        
        return subdomains

    def run_nmap(self, target):
        """
        Runs Nmap Fast Scan on the target.
        Command: nmap -F target.com -oX output.xml
        Returns: List of open ports/services.
        """
        output_file = os.path.join(self.output_dir, f"{target}_nmap.xml")
        
        if not shutil.which("nmap"):
            raise Exception("Nmap tool not found in system PATH.")

        # -F: Fast mode (scan fewer ports)
        # -oX: Output in XML format
        command = ["nmap", "-F", target, "-oX", output_file]
        
        print(f"[*] Running command: {' '.join(command)}")
        try:
            subprocess.run(
                command, 
                shell=False, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            print(f"[!] Command failed: {e.stderr}")
            # Nmap sometimes returns non-zero even on success if it finds nothing
            # But usually check=True is good.
            raise Exception(f"Nmap execution failed: {e.stderr}")

        return self._parse_nmap_xml(output_file)

    def _parse_nmap_xml(self, xml_file):
        """
        Parses Nmap XML output to extract open ports and services.
        """
        results = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                for ports in host.findall('ports'):
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_id = port.get('portid')
                            service = port.find('service')
                            service_name = service.get('name') if service is not None else "unknown"
                            results.append({
                                "port": int(port_id),
                                "protocol": port.get('protocol'),
                                "service": service_name
                            })
        except Exception as e:
            print(f"[!] XML Parsing error: {e}")
            
        return results

    def run_wappalyzer(self, url):
        """
        Detects technologies using Python-Wappalyzer.
        """
        # Ensure URL has schema
        if not url.startswith("http"):
            url = f"http://{url}"
            
        print(f"[*] Running Wappalyzer on: {url}")
        try:
            webpage = WebPage.new_from_url(url, verify=False)
            technologies = self.wappalyzer.analyze(webpage)
            return list(technologies)
        except Exception as e:
            print(f"[!] Wappalyzer failed: {e}")
            # Return empty list on failure (e.g., site not reachable)
            return []

if __name__ == "__main__":
    # Manual test
    manager = ScanManager()
    try:
        # Test Subfinder
        # results = manager.run_subfinder("scanme.nmap.org")
        # print(f"Found {len(results)} subdomains.")
        
        # Test Nmap
        print("Testing Nmap...")
        ports = manager.run_nmap("scanme.nmap.org")
        print(f"Nmap Results: {ports}")
        
        # Test Wappalyzer
        print("Testing Wappalyzer...")
        tech = manager.run_wappalyzer("http://scanme.nmap.org")
        print(f"Technologies: {tech}")
        
    except Exception as e:
        print(f"Error: {e}")
