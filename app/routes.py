from flask import Blueprint, render_template, jsonify, request
from app.tasks.recon import workflow_task
from app.tasks.attack import nuclei_scan, dalfox_scan, sqlmap_scan, wpscan_scan, commix_scan, nikto_scan
from app.celery_worker import hello_world_task
from app.analyzer import Analyzer
from app.db import get_scans_collection, get_attackable_urls_collection, get_redis_client, get_subdomains_collection, get_vulnerabilities_collection, get_technologies_collection, get_assets_collection
import datetime
from app.celery_worker import celery_app
from app.tasks.report import generate_report_task

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Mission Control Dashboard (One-Page Experience)."""
    scans_col = get_scans_collection()
    # Fetch master scans for sidebar
    scans = list(scans_col.find({"type": "master"}).sort("timestamp", -1))
    
    current_scan = None
    suggestions = []
    attackable_urls = []
    
    scan_id = request.args.get('scan_id')
    if scan_id:
        current_scan = scans_col.find_one({"scan_id": scan_id})
    elif scans:
        current_scan = scans[0]

    if current_scan:
        if 'suggestions' in current_scan:
            suggestions = current_scan['suggestions']
        # Fetch attackable URLs
        atk_col = get_attackable_urls_collection()
        atk_cursor = atk_col.find({"target": current_scan['target']})
        attackable_urls = [doc['url'] for doc in atk_cursor]
            
    return render_template('index.html', scans=scans, current_scan=current_scan, suggestions=suggestions, attackable_urls=attackable_urls)

@bp.route('/recon')
def recon_page():
    return render_template('recon.html')

import uuid

@bp.route('/api/create-target', methods=['POST'])
def create_target():
    """Create a new target (Master Scan) without starting a task."""
    data = request.get_json()
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
        
    scan_id = uuid.uuid4().hex
    
    # Create Master Scan Record with status 'created'
    get_scans_collection().insert_one({
        "target": target,
        "scan_id": scan_id,
        "type": "master",
        "status": "created",
        "timestamp": datetime.datetime.utcnow(),
        "tools": [] # No tools yet
    })
    
    return jsonify({
        'status': 'success', 
        'scan_id': scan_id,
        'message': 'Target created'
    }), 201

@bp.route('/start-recon', methods=['POST'])
def start_recon():
    """Trigger the Recon Workflow."""
    data = request.get_json()
    target = data.get('target')
    tools = data.get('tools', [])
    scan_id = data.get('scan_id') # Optional existing scan_id
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
        
    task = workflow_task.delay(target, tools, scan_id=scan_id)
    
    return jsonify({
        'status': 'success', 
        'task_id': task.id,
        'message': 'Recon started'
    }), 202

@bp.route('/start-task', methods=['POST'])
def start_task():
    """Trigger the Hello World Celery task."""
    task = hello_world_task.delay()
    return jsonify({
        'status': 'success', 
        'task_id': task.id,
        'message': 'Task submitted to Celery'
    }), 202

@bp.route('/dashboard')
def dashboard():
    """Mission Control Dashboard."""
    scans_col = get_scans_collection()
    # Fetch master scans
    scans = list(scans_col.find({"type": "master"}).sort("timestamp", -1))
    
    current_scan = None
    suggestions = []
    attackable_urls = []
    
    scan_id = request.args.get('scan_id')
    if scan_id:
        current_scan = scans_col.find_one({"scan_id": scan_id})
    elif scans:
        current_scan = scans[0]

    if current_scan:
        if 'suggestions' in current_scan:
            suggestions = current_scan['suggestions']
        # Fetch attackable URLs
        atk_col = get_attackable_urls_collection()
        atk_cursor = atk_col.find({"target": current_scan['target']})
        attackable_urls = [doc['url'] for doc in atk_cursor]
            
    return render_template('dashboard.html', scans=scans, current_scan=current_scan, suggestions=suggestions, attackable_urls=attackable_urls)

@bp.route('/api/analyze', methods=['POST'])
def analyze_target():
    """Run Analysis Engine on a target."""
    data = request.get_json()
    target = data.get('target')
    scan_id = data.get('scan_id')
    
    analyzer = Analyzer()
    suggestions = analyzer.analyze_target(target, scan_id)
    
    # Update DB
    get_scans_collection().update_one(
        {"scan_id": scan_id},
        {"$set": {
            "status": "analyzed",
            "suggestions": suggestions,
            "analyzed_at": datetime.datetime.utcnow()
        }}
    )
    
    return jsonify({'status': 'success', 'suggestions': suggestions})

@bp.route('/api/launch-attack', methods=['POST'])
def launch_attack():
    """Launch an attack tool."""
    data = request.get_json()
    scan_id = data.get('scan_id')
    tool = data.get('tool')
    # Use optional target override (e.g., specific http://site.com/vuln.php) or fallback to domain
    target_override = data.get('target') 
    
    scan = get_scans_collection().find_one({"scan_id": scan_id})
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Default to the main domain if no specific target is provided
    target = target_override if target_override else scan.get('target')

    # Trigger Celery tasks
    if tool == 'Nuclei':
        nuclei_scan.delay(target, scan_id)
    elif tool == 'Dalfox':
        dalfox_scan.delay(target, scan_id)
    elif tool == 'SQLMap':
        sqlmap_scan.delay(target, scan_id)
    elif tool == 'WPScan':
        wpscan_scan.delay(target, scan_id)
    elif tool == 'Commix':
        commix_scan.delay(target, scan_id)
    elif tool == 'Nikto':
        nikto_scan.delay(target, scan_id)
    
    get_scans_collection().update_one(
        {"scan_id": scan_id},
        {"$set": {
            "status": "attacking",
            "last_attack_tool": tool,
            "attack_started_at": datetime.datetime.utcnow()
        }}
    )
    
    # Add a log entry for immediate feedback
    r_client = get_redis_client()
    msg = f"[SYSTEM] Launching {tool} against {target}..."
    try:
        r_client.rpush(f"logs:{scan_id}", msg)
    except: pass
    
    return jsonify({'status': 'success', 'message': f'Launched {tool} on {target}'})

@bp.route('/api/logs/<scan_id>')
def get_scan_logs(scan_id):
    """Fetch recent logs for a scan."""
    r_client = get_redis_client()
    logs = r_client.lrange(f"logs:{scan_id}", 0, -1)
    return jsonify({'logs': logs})

@bp.route('/api/graph/<scan_id>')
def get_graph_data(scan_id):
    """Return graph data for Cytoscape."""
    scan = get_scans_collection().find_one({"scan_id": scan_id})
    if not scan:
        return jsonify([])
        
    target = scan.get('target')
    elements = []
    
    # 1. Central Target Node
    elements.append({'data': {'id': 'target', 'label': target, 'type': 'root'}})
    
    # 2. Subdomains
    sub_col = get_subdomains_collection()
    sub_docs = sub_col.find({"scan_id": scan_id}) # Or target? Better scan_id
    # Fallback to target if scan_id scan structure is loose
    if sub_col.count_documents({"scan_id": scan_id}) == 0:
        sub_docs = sub_col.find({"target": target})

    for doc in sub_docs:
        for sub in doc.get('subdomains', []):
            sub_id = sub
            elements.append({'data': {'id': sub_id, 'label': sub, 'type': 'subdomain'}})
            elements.append({'data': {'source': 'target', 'target': sub_id}})
            
    # 3. Technologies
    tech_col = get_technologies_collection()
    tech_docs = tech_col.find({"target": target}) # Techs are often target-bound
    seen_tech = set()
    for doc in tech_docs:
        name = doc.get('name')
        if name and name not in seen_tech:
            node_id = f"tech_{name}"
            elements.append({'data': {'id': node_id, 'label': name, 'type': 'tech'}})
            elements.append({'data': {'source': 'target', 'target': node_id}})
            seen_tech.add(name)
            
    # 4. Vulnerabilities
    vuln_col = get_vulnerabilities_collection()
    vuln_docs = vuln_col.find({"scan_id": scan_id})
    # Fallback
    if vuln_col.count_documents({"scan_id": scan_id}) == 0:
        vuln_docs = vuln_col.find({"target": target})
        
    for i, doc in enumerate(vuln_docs):
        # Determine label
        severity = doc.get('info', {}).get('severity', 'unknown') if 'info' in doc else 'unknown' # Nuclei
        if 'severity' in doc: severity = doc['severity'] # Custom
        
        name = doc.get('info', {}).get('name', 'Vuln') # Nuclei
        if 'tool' in doc and doc['tool'] == 'Dalfox': name = "XSS (Dalfox)"
        
        node_id = f"vuln_{i}"
        elements.append({'data': {'id': node_id, 'label': name, 'type': 'vuln', 'severity': severity}})
        elements.append({'data': {'source': 'target', 'target': node_id}})
        
    return jsonify(elements)

@bp.route('/api/stop-scan', methods=['POST'])
def stop_scan():
    """Revoke all tasks associated with a scan? Needs task IDs."""
    # Implementing generic revocation if task_id provided
    # Or implement a kill-switch for the current target?
    # Complex without tracking active task IDs.
    # We will assume we pass a task_id
    data = request.get_json()
    task_id = data.get('task_id')
    if task_id:
        celery_app.control.revoke(task_id, terminate=True)
        return jsonify({'status': 'stopped', 'message': f'Task {task_id} revoked.'})
    return jsonify({'error': 'No task ID provided'}), 400

@bp.route('/api/recon/<scan_id>')
def get_recon_data(scan_id):
    """Fetch all aggregated recon data for a scan."""
    results = {
        'subdomains': [],
        'technologies': [],
        'open_ports': [],
        'live_assets': [],
        'waf': []
    }
    
    # 1. Subdomains
    sub_col = get_subdomains_collection()
    sub_doc = sub_col.find_one({"scan_id": scan_id})
    if sub_doc and 'subdomains' in sub_doc:
        results['subdomains'] = sub_doc['subdomains']
        
    # 2. Technologies
    tech_col = get_technologies_collection()
    tech_docs = tech_col.find({"scan_id": scan_id})
    results['technologies'] = list(set(doc['name'] for doc in tech_docs if 'name' in doc))
    
    # 3. Nmap / Ports
    # Nmap results are stored in 'scans' collection with type='nmap'
    scans_col = get_scans_collection()
    nmap_doc = scans_col.find_one({"scan_id": scan_id, "type": "nmap"})
    if nmap_doc and 'results' in nmap_doc:
        results['open_ports'] = nmap_doc['results'] # List of dicts {port, service, protocol}
        
    # 4. Live Assets
    assets_col = get_assets_collection()
    asset_docs = assets_col.find({"scan_id": scan_id})
    for doc in asset_docs:
        results['live_assets'].append({
            'url': doc.get('domain'), # or construct URL
            'ip': doc.get('ip'),
            'status_code': doc.get('status_code'),
            'tech': doc.get('tech', [])
        })

    # 5. WAF
    # WAF is usually in the Master Scan 'results_summary' or we can log it separately
    # app/tasks/recon.py updates master scan results_summary['waf']
    master_scan = scans_col.find_one({"scan_id": scan_id, "type": "master"})
    if master_scan and 'results_summary' in master_scan:
        summary = master_scan['results_summary']
        if 'waf' in summary:
            results['waf'] = summary['waf']
        
        # Fallback/Merge if summary has recent data
        if not results['subdomains'] and 'subdomains' in summary:
             results['subdomains'] = summary['subdomains']
        if not results['technologies'] and 'technologies' in summary:
             results['technologies'] = summary['technologies']
             
    return jsonify(results)

@bp.route('/api/scan/<scan_id>/vulns')
def get_vulns(scan_id):
    """Fetch all vulnerabilities/findings for a scan."""
    vuln_col = get_vulnerabilities_collection()
    findings = list(vuln_col.find({"scan_id": scan_id}).sort("severity", 1)) 
    
    clean_findings = []
    for f in findings:
        # Normalize fields for Frontend
        if '_id' in f: del f['_id']
        
        # 1. Normalize Severity
        # Dalfox: severity (TitleCase)
        # Nuclei: info.severity (lowercase)
        # WPScan: severity (TitleCase)
        sev = f.get('severity')
        if not sev and 'info' in f and 'severity' in f['info']:
            sev = f['info']['severity']
        if not sev: sev = 'Info'
        f['severity'] = str(sev).upper() # HIGH, MEDIUM, LOW
        
        # 2. Normalize Name
        # Dalfox: message_str or name? Dalfox has CWE often.
        # Nuclei: info.name
        name = f.get('name')
        if not name and 'info' in f and 'name' in f['info']:
            name = f['info']['name']
        if not name and 'message_str' in f:
            name = f['message_str']
        f['name'] = name or 'Unknown Issue'
        
        clean_findings.append(f)
            
    return jsonify({'findings': clean_findings})

@bp.route('/api/generate-report', methods=['POST'])
def generate_report():
    """Trigger report generation."""
    data = request.get_json()
    scan_id = data.get('scan_id')
    format_type = data.get('format', 'pdf')  # pdf or html
    
    if not scan_id:
        return jsonify({'error': 'scan_id required'}), 400
    
    # Trigger Celery task
    task = generate_report_task.delay(scan_id, format_type)
    
    return jsonify({
        'status': 'success',
        'task_id': task.id,
        'message': 'Report generation started'
    }), 202

@bp.route('/api/download-report/<scan_id>')
def download_report(scan_id):
    """Download generated report."""
    from flask import send_file
    import os
    
    scan = get_scans_collection().find_one({"scan_id": scan_id})
    if not scan or 'report_path' not in scan:
        return jsonify({'error': 'Report not found'}), 404
    
    report_path = scan['report_path']
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report file not found on server'}), 404
    
    # Use absolute path to be safe
    abs_path = os.path.abspath(report_path)
    return send_file(abs_path, as_attachment=True)
