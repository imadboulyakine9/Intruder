import subprocess
import os
import shutil
import json

class ScanManager:
    """
    Wrapper class for external security tools (Subfinder, Nmap, etc.).
    Handles subprocess execution and output file management.
    """

    def __init__(self, output_dir="scans"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

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

if __name__ == "__main__":
    # Manual test
    manager = ScanManager()
    try:
        results = manager.run_subfinder("scanme.nmap.org")
        print(f"Found {len(results)} subdomains.")
        print(results)
    except Exception as e:
        print(f"Error: {e}")
