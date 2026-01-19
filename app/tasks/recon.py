from app.celery_worker import celery_app, socketio
from app.scan_manager import ScanManager
from app.db import get_subdomains_collection, get_scans_collection
import datetime

@celery_app.task(bind=True)
def subdomain_scan(self, target):
    """
    Celery task to run Subfinder on a target.
    """
    scan_id = self.request.id
    manager = ScanManager()
    
    try:
        # Notify start
        socketio.emit('task_update', {
            'status': f'Starting subdomain scan for {target}...',
            'percent': 10
        })
        
        # database - create scan record (if not exists logic should be here, or passed in)
        # For now, let's just log it
        
        # Run Subfinder
        subdomains = manager.run_subfinder(target)
        
        socketio.emit('task_update', {
            'status': f'Found {len(subdomains)} subdomains. Saving to DB...',
            'percent': 80
        })

        # Save to MongoDB
        # We'll save a simple document for now matching Step 18 plan
        # { "target": "site.com", "subdomains": [...] }
        
        # Note: Step 18 mentions "DB Save", I'm doing it here or in a separate step.
        # I'll do it here to make the task complete.
        
        collection = get_subdomains_collection()
        
        # Prepare documents for subdomains
        # We might want to store them individually or as a list in one doc. 
        # The prompt said: { "target": "site.com", "subdomains": [...] }
        
        doc = {
            "target": target,
            "scan_id": scan_id,
            "timestamp": datetime.datetime.utcnow(),
            "subdomains": subdomains,
            "count": len(subdomains)
        }
        
        collection.insert_one(doc)

        socketio.emit('task_update', {
            'status': 'Scan Complete.',
            'percent': 100,
            'result': subdomains
        })

        return {
            'status': 'COMPLETED',
            'target': target,
            'subdomains_found': len(subdomains)
        }

    except Exception as e:
        socketio.emit('task_update', {'status': 'Error during scan', 'percent': 0, 'error': str(e)})
        raise e
