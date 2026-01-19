"""
Celery worker configuration for Intruder (Jarvis).
Configures Redis as the broker and MongoDB as the result backend.
"""

from celery import Celery
from flask_socketio import SocketIO
import os
from dotenv import load_dotenv

load_dotenv()

# Redis Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", 6379)
REDIS_DB = os.getenv("REDIS_DB", 0)
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

# MongoDB Configuration for result backend
MONGO_RESULT_HOST = os.getenv("MONGO_RESULT_HOST", "localhost")
MONGO_RESULT_PORT = os.getenv("MONGO_RESULT_PORT", 27017)
MONGO_RESULT_DB = os.getenv("MONGO_RESULT_DB", "intruder_celery")

# Initialize Celery app
celery_app = Celery('intruder')

# Initialize SocketIO for emitting events from Celery
socketio = SocketIO(message_queue=REDIS_URL)

# Celery Configuration
celery_app.conf.update(
    # Broker settings (Redis)
    broker_url=REDIS_URL,
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
    
    # Result backend settings (MongoDB)
    result_backend=f"mongodb://{MONGO_RESULT_HOST}:{MONGO_RESULT_PORT}/{MONGO_RESULT_DB}",
    result_expires=3600,  # 1 hour
    
    # Task settings
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
    
    # Task execution settings
    task_track_started=True,
    task_send_sent_event=True,
    worker_send_task_events=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,  # One task at a time per worker
    
    # Worker settings
    worker_max_tasks_per_child=1000,
    worker_disable_rate_limits=False,
    
    # Routing
    task_routes={
        'intruder.tasks.recon.*': {'queue': 'recon'},
        'intruder.tasks.attack.*': {'queue': 'attack'},
        'intruder.tasks.analysis.*': {'queue': 'analysis'},
    },
    
    # Queue settings
    task_default_queue='default',
    task_default_exchange='intruder',
    task_default_routing_key='default',
)

# Define queues
from kombu import Exchange, Queue

default_exchange = Exchange('intruder', type='direct')

celery_app.conf.task_queues = (
    Queue('default', exchange=default_exchange, routing_key='default'),
    Queue('recon', exchange=default_exchange, routing_key='recon'),
    Queue('attack', exchange=default_exchange, routing_key='attack'),
    Queue('analysis', exchange=default_exchange, routing_key='analysis'),
)

# Auto-discover tasks from the tasks module
# celery_app.autodiscover_tasks(['app.tasks'])
# Explicitly import tasks to ensure registration
import app.tasks.recon


@celery_app.task(bind=True)
def debug_task(self):
    """A simple debug task to test Celery is working."""
    print(f'Request: {self.request!r}')
    return "✓ Celery is working!"


@celery_app.task(bind=True)
def hello_world_task(self):
    """
    Hello World Celery task - Phase 1, Step 9.
    Waits 5 seconds and returns "Task Complete".
    Emits progress updates via WebSocket.
    """
    try:
        # Emit initial status
        socketio.emit('task_update', {'status': 'Started', 'percent': 0})
        self.update_state(state='PROGRESS', meta={'current': 0, 'total': 5})
        
        import time
        for i in range(5):
            time.sleep(1)
            progress = int((i + 1) / 5 * 100)
            
            # Emit to WebSocket
            socketio.emit('task_update', {'status': 'Processing...', 'percent': progress})
            
            self.update_state(
                state='PROGRESS',
                meta={'current': i + 1, 'total': 5, 'percent': progress}
            )
            print(f"Progress: {progress}%")
        
        # Emit completion
        socketio.emit('task_update', {'status': 'Complete', 'percent': 100})
        
        return {
            'status': 'COMPLETED',
            'result': 'Task Complete',
            'message': '✓ Hello World Task Completed'
        }
    except Exception as e:
        socketio.emit('task_update', {'status': 'Error', 'percent': 0, 'error': str(e)})
        self.update_state(
            state='FAILURE',
            meta={'exc_type': type(e).__name__, 'exc_message': str(e)}
        )
        raise


if __name__ == '__main__':
    celery_app.start()
