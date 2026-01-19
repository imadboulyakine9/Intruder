from flask import Blueprint, render_template, jsonify, request
from app.tasks.recon import workflow_task
from app.tasks.attack import nuclei_scan, dalfox_scan
from app.celery_worker import hello_world_task
from app.analyzer import Analyzer
from app.db import get_scans_collection, get_attackable_urls_collection, get_redis_client, get_subdomains_collection, get_vulnerabilities_collection, get_technologies_collection
import datetime
from app.celery_worker import celery_app

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

@bp.route('/start-recon', methods=['POST'])
def start_recon():
    """Trigger the Recon Workflow."""
    data = request.get_json()
    target = data.get('target')
    tools = data.get('tools', [])
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
        
    task = workflow_task.delay(target, tools)
    
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
    suggestions = analyzer.analyze_target(target)
    
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
    
    scan = get_scans_collection().find_one({"scan_id": scan_id})
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    target = scan.get('target')

    # Trigger Celery tasks
    if tool == 'Nuclei':
        nuclei_scan.delay(target, scan_id)
    elif tool == 'Dalfox':
        dalfox_scan.delay(target, scan_id)
    
    get_scans_collection().update_one(
        {"scan_id": scan_id},
        {"$set": {
            "status": "attacking",
            "last_attack_tool": tool,
            "attack_started_at": datetime.datetime.utcnow()
        }}
    )
    
    return jsonify({'status': 'success', 'message': f'Launched {tool}'})

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
