from app.celery_worker import celery_app, socketio
from app.scan_manager import ScanManager
from app.db import get_vulnerabilities_collection, get_scans_collection
import datetime
import os

@celery_app.task(bind=True)
def nuclei_scan(self, target, scan_id=None):
    """
    Celery task to run Nuclei.
    """
    manager = ScanManager()
    
    def on_output(line):
        socketio.emit('tool_output', {'line': line, 'tool': 'Nuclei', 'scan_id': scan_id})

    socketio.emit('task_update', {'status': f'Starting Nuclei scan on {target}...', 'percent': 10, 'scan_id': scan_id})
    
    findings = manager.run_nuclei(target, callback=on_output)
    
    # Save findings
    if findings:
        vuln_col = get_vulnerabilities_collection()
        for item in findings:
            item['scan_id'] = scan_id
            item['target'] = target
            item['tool'] = 'Nuclei'
            item['discovered_at'] = datetime.datetime.utcnow()
            vuln_col.insert_one(item)
            
    socketio.emit('task_update', {'status': f'Nuclei completed. Found {len(findings)} issues.', 'percent': 100, 'scan_id': scan_id})
    return {'tool': 'Nuclei', 'count': len(findings)}

@celery_app.task(bind=True)
def dalfox_scan(self, target, scan_id=None):
    """
    Celery task to run Dalfox.
    Requires a file of URLs. We might need to generate it from DB if not passed directly.
    For this task, we assume 'target' might be a domain, and we look up URLs or it's a file path.
    Actually, 'launch_attack' in routes passes 'tool' and 'scan_id'.
    We need to fetch URLs for the target.
    """
    manager = ScanManager()
    
    # Fetch URLs for target from DB or assumption
    # In Phase 3, we collected attackable URLs.
    from app.db import get_attackable_urls_collection, get_subdomains_collection
    
    # Identify target domain from scan_id if not explicitly passed?
    # self.request.args usually has arguments if called via apply_async
    
    # Let's assume 'target' is the domain.
    # We need to create a temporary file of URLs for Dalfox
    
    # 1. Gather URLs
    urls = set()
    
    # From attackable_urls (high priority)
    atk_col = get_attackable_urls_collection()
    cursor = atk_col.find({"target": target})
    for doc in cursor:
        if 'url' in doc: urls.add(doc['url'])
        
    # From subdomains (as simple urls)
    sub_col = get_subdomains_collection()
    sub_cursor = sub_col.find({"target": target})
    for doc in sub_cursor:
        if 'subdomains' in doc:
            for sub in doc['subdomains']:
                urls.add(f"http://{sub}")
                urls.add(f"https://{sub}")
                
    if not urls:
        # Fallback: just the target itself
        urls.add(f"http://{target}")
        urls.add(f"https://{target}")
        
    # Write to temp file
    urls_file = os.path.join(manager.output_dir, f"{target}_urls_for_dalfox.txt")
    with open(urls_file, 'w') as f:
        for u in urls:
            f.write(u + '\n')
            
    def on_output(line):
        socketio.emit('tool_output', {'line': line, 'tool': 'Dalfox', 'scan_id': scan_id})

    socketio.emit('task_update', {'status': f'Starting Dalfox scan on {len(urls)} URLs...', 'percent': 10, 'scan_id': scan_id})

    pocs = manager.run_dalfox(urls_file, callback=on_output)
    
    # Save findings
    if pocs:
        vuln_col = get_vulnerabilities_collection()
        for item in pocs:
            item['scan_id'] = scan_id
            item['target'] = target
            item['tool'] = 'Dalfox'
            item['discovered_at'] = datetime.datetime.utcnow()
            # Dalfox JSON structure usually has 'type', 'poc', 'param' etc.
            vuln_col.insert_one(item)

    socketio.emit('task_update', {'status': f'Dalfox completed. Found {len(pocs)} PoCs.', 'percent': 100, 'scan_id': scan_id})
    return {'tool': 'Dalfox', 'count': len(pocs)}
