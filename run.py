import eventlet
eventlet.monkey_patch()

from app import create_app, socketio

app = create_app()

if __name__ == '__main__':
    # Run using SocketIO's web server (eventlet/gevent)
    print("🚀 Starting Intruder Server on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

