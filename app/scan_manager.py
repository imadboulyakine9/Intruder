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

    def _run_command(self, command, timeout=300):
        """
        Helper to run shell commands safely with valid timeout.
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
                text=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"[!] Command timed out after {timeout} seconds: {command}")
            raise Exception(f"Tool execution timed out after {timeout}s")
        except subprocess.CalledProcessError as e:
            print(f"[!] Command failed: {e.stderr}")
            raise Exception(f"Tool execution failed: {e.stderr}")

    def run_httpx(self, target_file):
        """
        Runs httpx on a list of subdomains to find live hosts.
        Command: httpx-toolkit -l subdomains.txt -o live.txt -json
        """
        base_name = os.path.basename(target_file).replace('_subdomains.txt', '')
        output_file = os.path.join(self.output_dir, f"{base_name}_live.json")
        
        # Determine the correct binary name
        # Kali installs it as 'httpx-toolkit', others might use 'httpx'
        httpx_bin = "httpx"
        if shutil.which("httpx-toolkit"):
            httpx_bin = "httpx-toolkit"
        elif shutil.which("httpx"):
            # Verify if it's the Go tool (supports -version)
            try:
                subprocess.run(["httpx", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                httpx_bin = "httpx"
            except:
                # Likely the python lib, keep searching or fail
                print("[!] 'httpx' command seems to be the Python library. Please install the Go tool (httpx-toolkit).")
                # We could try to proceed, but it will likely fail.
                pass
        
        if not shutil.which(httpx_bin):
            print("[!] httpx tool not found. Skipping live check.")
            return []

        # -l: input list
        # -json: json output
        # -o: output file
        # -silent: less noise
        command = [httpx_bin, "-l", target_file, "-json", "-o", output_file, "-silent"]
        
        print(f"[*] Running command: {' '.join(command)}")
        try:
            subprocess.run(
                command, 
                shell=False, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=300 # 5 minutes
            )
        except subprocess.TimeoutExpired:
            raise Exception("httpx timed out")
        except subprocess.CalledProcessError as e:
            print(f"[!] httpx failed: {e.stderr}")
            raise Exception(f"httpx execution failed: {e.stderr}")

        # Parse JSON results
        live_hosts = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            # httpx outputs one JSON object per line using -json
                            data = json.loads(line)
                            live_hosts.append(data)
                        except:
                            pass
        
        return live_hosts

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
                text=True,
                timeout=300
            )
        except subprocess.TimeoutExpired:
            raise Exception("Subfinder timed out")
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
                stderr=subprocess.PIPE,
                timeout=600 # 10 minutes for Nmap
            )
        except subprocess.TimeoutExpired:
            raise Exception("Nmap scan timed out")
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
            # Suppress DeprecationWarnings from Wappalyzer/pkg_resources
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                webpage = WebPage.new_from_url(url, verify=False)
                technologies = self.wappalyzer.analyze(webpage)
            return list(technologies)
        except Exception as e:
            print(f"[!] Wappalyzer failed for {url}: {e}")
            # Try HTTPS if HTTP failed and it wasn't specified
            if url.startswith("http://"):
                 try:
                    https_url = url.replace("http://", "https://")
                    print(f"[*] Retrying Wappalyzer with: {https_url}")
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        webpage = WebPage.new_from_url(https_url, verify=False)
                        technologies = self.wappalyzer.analyze(webpage)
                    return list(technologies)
                 except:
                     pass
            # Return empty list on failure (e.g., site not reachable)
            return []

    def run_wafw00f(self, target):
        """
        Detects WAF using wafw00f.
        Command: wafw00f target.com -o output.json
        """
        output_file = os.path.join(self.output_dir, f"{target}_waf.json")
        
        if not shutil.which("wafw00f"):
            raise Exception("wafw00f tool not found in system PATH.")

        # -o: output file
        # -f: json format (implied by file extension in newer versions or handled by wrapper)
        # wafw00f output handling is tricky. It prints to stdout. 
        # The -o option might just save the structured log. 
        # Let's try capturing stdout or use specific flags.
        # Wafw00f v2.3.1 supports -o output_file.
        
        command = ["wafw00f", target, "-o", output_file]
        
        print(f"[*] Running command: {' '.join(command)}")
        try:
            # wafw00f might return non-zero if no WAF found? No, usually 0.
            subprocess.run(
                command, 
                shell=False, 
                check=False, # Don't raise on non-zero, wafw00f might behave differently
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=180
            )
        except subprocess.TimeoutExpired:
            raise Exception("wafw00f timed out")
        except Exception as e:
            print(f"[!] wafw00f failed: {e}")
            raise

        # Parse the JSON output
        results = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    # Support list or dict structure depending on version
                    if isinstance(data, list):
                        results = data
                    else:
                        results = [data]
            except Exception as e:
                print(f"[!] JSON Parsing error (wafw00f): {e}")
                
        return results

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
