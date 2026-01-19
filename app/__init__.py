from flask import Flask
from flask_socketio import SocketIO
import os

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret!')

    # Redis URL for SocketIO message queue
    redis_host = os.getenv('REDIS_HOST', 'localhost')
    redis_port = os.getenv('REDIS_PORT', 6379)
    redis_url = f"redis://{redis_host}:{redis_port}/0"

    # Initialize SocketIO
    # message_queue argument allows external processes (Celery) to emit events
    socketio.init_app(app, message_queue=redis_url, async_mode='eventlet')

    from app import routes
    app.register_blueprint(routes.bp)

    return app
