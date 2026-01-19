from flask import Blueprint, render_template, jsonify, request
from app.tasks.recon import workflow_task
from app.celery_worker import hello_world_task

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
