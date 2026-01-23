from app.tasks.recon import subdomain_scan, nmap_scan, tech_detection_task
import time

def trigger_full_recon():
    target_domain = "scanme.nmap.org"
    target_url = "http://scanme.nmap.org"
    
    print(f"🚀 Triggering Full Recon for: {target_domain}")
    
    # 1. Subfinder
    print("[1/3] Dispatching Subdomain Scan...")
    task1 = subdomain_scan.delay(target_domain)
    print(f"   -> Task ID: {task1.id}")

    # 2. Nmap
    print("[2/3] Dispatching Nmap Scan...")
    task2 = nmap_scan.delay(target_domain)
    print(f"   -> Task ID: {task2.id}")

    # 3. Wappalyzer
    print("[3/3] Dispatching Tech Detection...")
    task3 = tech_detection_task.delay(target_url)
    print(f"   -> Task ID: {task3.id}")
    
    print("\n✅ All tasks dispatched! Check Celery Worker terminal for results.")

if __name__ == "__main__":
    trigger_full_recon()
