from app.tasks.recon import subdomain_scan
import time

def trigger_test_scan():
    target = "scanme.nmap.org"
    print(f"🚀 Triggering Subdomain Scan for: {target}")
    
    # Send task to Celery
    task = subdomain_scan.delay(target)
    print(f"✅ Task Dispatched! ID: {task.id}")
    print("⏳ Waiting for results (Check Celery Worker terminal for logs)...")

if __name__ == "__main__":
    trigger_test_scan()
