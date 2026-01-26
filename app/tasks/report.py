from app.celery_worker import celery_app, socketio
from app.report_generator import ReportGenerator
from app.db import get_scans_collection
import datetime
import os

@celery_app.task(bind=True)
def generate_report_task(self, scan_id, format='pdf'):
    """
    Generate a comprehensive report for a scan.
    Supports PDF and HTML formats.
    """
    try:
        socketio.emit('task_update', {
            'scan_id': scan_id,
            'status': 'Generating report...',
            'percent': 10
        })
        
        # Initialize generator
        generator = ReportGenerator(scan_id)
        
        socketio.emit('task_update', {
            'scan_id': scan_id,
            'status': 'Collecting scan data...',
            'percent': 30
        })
        
        # Generate report
        if format == 'pdf':
            report_path = generator.generate_pdf()
        else:
            report_path = generator.generate_html()
        
        socketio.emit('task_update', {
            'scan_id': scan_id,
            'status': 'Report generated successfully!',
            'percent': 100,
            'report_path': report_path
        })
        
        # Update scan record
        get_scans_collection().update_one(
            {"scan_id": scan_id},
            {"$set": {
                "report_path": report_path,
                "report_generated_at": datetime.datetime.utcnow()
            }}
        )
        
        return {
            'status': 'COMPLETED',
            'report_path': report_path
        }
        
    except Exception as e:
        socketio.emit('task_update', {
            'scan_id': scan_id,
            'status': f'Error: {str(e)}',
            'percent': 0
        })
        raise
