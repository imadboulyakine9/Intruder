from flask import Blueprint, render_template, jsonify
from app.celery_worker import hello_world_task

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/start-task', methods=['POST'])
def start_task():
    """Trigger the Hello World Celery task."""
    task = hello_world_task.delay()
    return jsonify({
        'status': 'success', 
        'task_id': task.id,
        'message': 'Task submitted to Celery'
    }), 202
