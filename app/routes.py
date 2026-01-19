from flask import Blueprint, render_template, jsonify, request
from app.tasks.recon import workflow_task
from app.celery_worker import hello_world_task
from app.analyzer import Analyzer
from app.db import get_scans_collection, get_attackable_urls_collection
import datetime

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return render_template('index.html')

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
    
    # In Phase 4, we will actually trigger Celery tasks here.
    # For now, just update status.
    
    get_scans_collection().update_one(
        {"scan_id": scan_id},
        {"$set": {
            "status": "attacking",
            "last_attack_tool": tool,
            "attack_started_at": datetime.datetime.utcnow()
        }}
    )
    
    return jsonify({'status': 'success', 'message': f'Launched {tool}'})
