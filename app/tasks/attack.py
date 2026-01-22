from app.celery_worker import celery_app, socketio
from app.scan_manager import ScanManager
from app.db import get_vulnerabilities_collection, get_scans_collection, get_redis_client
import datetime
import os

@celery_app.task(bind=True)
def nuclei_scan(self, target, scan_id=None):
    """
    Celery task to run Nuclei.
    """
    manager = ScanManager()
    r_client = get_redis_client()
    
    def on_output(line):
        socketio.emit('tool_output', {'line': line, 'tool': 'Nuclei', 'scan_id': scan_id})
        if scan_id:
            try:
                r_client.rpush(f"logs:{scan_id}", f"[Nuclei] {line}")
                r_client.ltrim(f"logs:{scan_id}", -50, -1) # Keep last 50 lines
            except Exception as e:
                socketio.emit('tool_output', {'line': f"[Redis Error] {e}", 'tool': 'Nuclei', 'scan_id': scan_id})

    socketio.emit('task_update', {'status': f'Starting Nuclei scan on {target}...', 'percent': 10, 'scan_id': scan_id})
    if scan_id:
        r_client.rpush(f"logs:{scan_id}", f"[SYSTEM] Starting Nuclei scan on {target}...")
    
    # Update templates first (Step 36)
    manager.update_nuclei(callback=on_output)
    
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
        if 'url' in doc:
            urls.add(doc['url'])
    # From subdomains (as simple urls)
    sub_col = get_subdomains_collection()
    sub_cursor = sub_col.find({"target": target})
    for doc in sub_cursor:
        if 'subdomains' in doc:
            for sub in doc['subdomains']:
                urls.add(f"http://{sub}")
                urls.add(f"https://{sub}")
    # Fallback: just the target itself if no URLs found in DB
    if not urls:
        urls.add(f"http://{target}")
        urls.add(f"https://{target}")
        
    # Write to temp file
    urls_file = os.path.join(manager.output_dir, f"{target}_urls_for_dalfox.txt")
    with open(urls_file, 'w') as f:
        for u in urls:
            f.write(u + '\n')
            
    r_client = get_redis_client()

    def on_output(line):
        socketio.emit('tool_output', {'line': line, 'tool': 'Dalfox', 'scan_id': scan_id})
        if scan_id:
            try:
                r_client.rpush(f"logs:{scan_id}", f"[Dalfox] {line}")
                r_client.ltrim(f"logs:{scan_id}", -50, -1)
            except Exception as e:
                socketio.emit('tool_output', {'line': f"[Redis Error] {e}", 'tool': 'Dalfox', 'scan_id': scan_id})

    socketio.emit('task_update', {'status': f'Starting Dalfox scan on {len(urls)} URLs...', 'percent': 10, 'scan_id': scan_id})
    if scan_id:
        r_client.rpush(f"logs:{scan_id}", f"[SYSTEM] Starting Dalfox scan on {len(urls)} URLs...")

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

@celery_app.task(bind=True)
def sqlmap_scan(self, target, scan_id=None):
    """
    Celery task to run SQLMap.
    Target MUST be a URL with parameters.
    """
    manager = ScanManager()
    r_client = get_redis_client()

    def on_output(line):
        socketio.emit('tool_output', {'line': line, 'tool': 'SQLMap', 'scan_id': scan_id})
        if scan_id:
            try:
                r_client.rpush(f"logs:{scan_id}", f"[SQLMap] {line}")
                r_client.ltrim(f"logs:{scan_id}", -50, -1)
            except Exception as e:
                socketio.emit('tool_output', {'line': f"[Redis Error] {e}", 'tool': 'SQLMap', 'scan_id': scan_id})

    # Ensure target includes http:// or https://
    if not (target.startswith('http://') or target.startswith('https://')):
        target = f"http://{target}"
    socketio.emit('task_update', {'status': f'Starting SQLMap on {target}...', 'percent': 10, 'scan_id': scan_id})
    findings = manager.run_sqlmap(target, callback=on_output)
    
    if findings:
        vuln_col = get_vulnerabilities_collection()
        for item in findings:
            item['scan_id'] = scan_id
            item['target'] = target
            item['tool'] = 'SQLMap'
            item['severity'] = 'Critical' # SQLi is usually Critical
            item['name'] = 'SQL Injection Detected'
            item['discovered_at'] = datetime.datetime.utcnow()
            vuln_col.insert_one(item)
            
    socketio.emit('task_update', {'status': f'SQLMap completed. Found {len(findings)} injection points.', 'percent': 100, 'scan_id': scan_id})
    return {'tool': 'SQLMap', 'count': len(findings)}

@celery_app.task(bind=True)
def wpscan_scan(self, target, scan_id=None):
    """
    Celery task to run WPScan.
    """
    manager = ScanManager()
    r_client = get_redis_client()

    def on_output(line):
        socketio.emit('tool_output', {'line': line, 'tool': 'WPScan', 'scan_id': scan_id})
        if scan_id:
            try:
                r_client.rpush(f"logs:{scan_id}", f"[WPScan] {line}")
            except Exception as e:
                socketio.emit('tool_output', {'line': f"[Redis Error] {e}", 'tool': 'WPScan', 'scan_id': scan_id})

    socketio.emit('task_update', {'status': f'Starting WPScan on {target}...', 'percent': 10, 'scan_id': scan_id})
    
    findings = manager.run_wpscan(target, callback=on_output)
    
    if findings:
        vuln_col = get_vulnerabilities_collection()
        for item in findings:
            item['scan_id'] = scan_id
            item['target'] = target
            item['tool'] = 'WPScan'
            item['discovered_at'] = datetime.datetime.utcnow()
            vuln_col.insert_one(item)
            
    socketio.emit('task_update', {'status': f'WPScan completed. Found {len(findings)} issues.', 'percent': 100, 'scan_id': scan_id})
    return {'tool': 'WPScan', 'count': len(findings)}

@celery_app.task(bind=True)
def commix_scan(self, target, scan_id=None):
    """
    Celery task to run Commix.
    """
    manager = ScanManager()
    r_client = get_redis_client()

    def on_output(line):
        socketio.emit('tool_output', {'line': line, 'tool': 'Commix', 'scan_id': scan_id})
        if scan_id:
            try:
                r_client.rpush(f"logs:{scan_id}", f"[Commix] {line}")
            except Exception as e:
                socketio.emit('tool_output', {'line': f"[Redis Error] {e}", 'tool': 'Commix', 'scan_id': scan_id})

    socketio.emit('task_update', {'status': f'Starting Commix on {target}...', 'percent': 10, 'scan_id': scan_id})
    
    manager.run_commix(target, callback=on_output)
    
    socketio.emit('task_update', {'status': 'Commix completed. Check logs for details.', 'percent': 100, 'scan_id': scan_id})
    return {'tool': 'Commix', 'count': 0}

@celery_app.task(bind=True)
def nikto_scan(self, target, scan_id=None):
    """
    Celery task to run Nikto.
    """
    manager = ScanManager()
    r_client = get_redis_client()

    def on_output(line):
        socketio.emit('tool_output', {'line': line, 'tool': 'Nikto', 'scan_id': scan_id})
        if scan_id:
            try:
                r_client.rpush(f"logs:{scan_id}", f"[Nikto] {line}")
                r_client.ltrim(f"logs:{scan_id}", -50, -1)
            except Exception as e:
                socketio.emit('tool_output', {'line': f"[Redis Error] {e}", 'tool': 'Nikto', 'scan_id': scan_id})

    socketio.emit('task_update', {'status': f'Starting Nikto scan on {target}...', 'percent': 10, 'scan_id': scan_id})
    if scan_id:
        r_client.rpush(f"logs:{scan_id}", f"[SYSTEM] Starting Nikto scan on {target}...")

    findings = manager.run_nikto(target, callback=on_output)

    if findings:
        vuln_col = get_vulnerabilities_collection()
        for item in findings:
            item['scan_id'] = scan_id
            item['target'] = target
            item['tool'] = 'Nikto'
            item['name'] = item.get('msg', 'Nikto Finding')
            item['discovered_at'] = datetime.datetime.utcnow()
            vuln_col.insert_one(item)

    socketio.emit('task_update', {'status': f'Nikto completed. Found {len(findings)} issues.', 'percent': 100, 'scan_id': scan_id})
    return {'tool': 'Nikto', 'count': len(findings)}
