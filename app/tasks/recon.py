from app.celery_worker import celery_app, socketio
from app.scan_manager import ScanManager
from app.db import get_subdomains_collection, get_scans_collection, get_technologies_collection, get_vulnerabilities_collection # Assuming we might use vulnerabilities later
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
        
        # Run Subfinder
        subdomains = manager.run_subfinder(target)
        
        socketio.emit('task_update', {
            'status': f'Found {len(subdomains)} subdomains. Saving to DB...',
            'percent': 30
        })

        # Save to MongoDB
        collection = get_subdomains_collection()
        doc = {
            "target": target,
            "scan_id": scan_id,
            "timestamp": datetime.datetime.utcnow(),
            "subdomains": subdomains,
            "count": len(subdomains)
        }
        collection.insert_one(doc)

        # Trigger next steps? Or let the user trigger them?
        # For now, let's keep them as independent tasks, or allow the UI to chain them.
        # But for Phase 2 "Recon Module", typically we run all recon.
        # The prompt asks for "Nmap Task", "Tech Detection".
        
        return {
            'status': 'COMPLETED',
            'target': target,
            'subdomains_found': len(subdomains),
            'subdomains': subdomains
        }

    except Exception as e:
        socketio.emit('task_update', {'status': 'Error during scan', 'percent': 0, 'error': str(e)})
        raise e

@celery_app.task(bind=True)
def nmap_scan(self, target):
    """
    Celery task to run Nmap on a target.
    """
    scan_id = self.request.id
    manager = ScanManager()

    try:
        socketio.emit('task_update', {
            'status': f'Starting Nmap scan for {target}...',
            'percent': 10
        })

        results = manager.run_nmap(target)
        
        socketio.emit('task_update', {
            'status': f'Nmap complete. Found {len(results)} open ports.',
            'percent': 80
        })

        # Save results - reusing subdomains collection for now or maybe create a new 'ports' collection?
        # The prompt didn't specify a 'ports' collection, but implied saving parsing results.
        # Step 19: "Parse XML output".
        # Let's update the subdomains or scans collection, OR make a simple 'findings' collection?
        # Step 18 said "Save subdomains", Step 35 says "Store discovered Attackable URLs".
        # Let's store nmap results in a generic 'scan_results' or append to the scan document.
        # I'll just save it to a new 'services' collection or similar, or just return it for now if DB schema isn't strict.
        # Let's put it in `scans` collection under the specific scan ID if we had one, but we generate new scan IDs per task.
        # I'll add it to a 'services' collection.
        
        # Actually, let's just log it and return it for Phase 2.
        # Wait, Step 25 says "Ensure data appears in MongoDB Compass".
        # So I really should save it. I'll use `technologies` for tech and maybe `services` for nmap?
        # I'll check db.py... we have `get_subdomains_collection`, `get_technologies_collection`. We lack `get_services_collection`.
        # I'll add `services` collection usage here dynamically or just use `vulnerabilities`? No, ports aren't vulns.
        # I'll simply store it in `scans` collection as a new document type="nmap_result".
        
        scans_col = get_scans_collection()
        scans_col.insert_one({
            "target": target,
            "scan_id": scan_id,
            "type": "nmap_scan",
            "timestamp": datetime.datetime.utcnow(),
            "results": results
        })

        return {
            'status': 'COMPLETED',
            'target': target,
            'open_ports': len(results),
            'results': results
        }

    except Exception as e:
        socketio.emit('task_update', {'status': 'Error during Nmap scan', 'percent': 0, 'error': str(e)})
        raise e


@celery_app.task(bind=True)
def tech_detection_task(self, target):
    """
    Celery task to detect technologies using Wappalyzer.
    """
    scan_id = self.request.id
    manager = ScanManager()

    try:
        socketio.emit('task_update', {
            'status': f'Identifying technologies for {target}...',
            'percent': 10
        })

        technologies = manager.run_wappalyzer(target)
        
        socketio.emit('task_update', {
            'status': f'Identified {len(technologies)} technologies.',
            'percent': 80
        })

        # DB Save
        tech_col = get_technologies_collection()
        for tech in technologies:
            tech_col.insert_one({
                "target": target,
                "scan_id": scan_id,
                "name": tech,
                "timestamp": datetime.datetime.utcnow()
            })

        return {
            'status': 'COMPLETED',
            'target': target,
            'technologies': technologies
        }

    except Exception as e:
        socketio.emit('task_update', {'status': 'Error during Tech Detection', 'percent': 0, 'error': str(e)})
        raise e

@celery_app.task(bind=True)
def workflow_task(self, target, tools):
    """
    Orchestrator task to run multiple recon tools sequentially or in parallel.
    tools: list of strings ['subfinder', 'nmap', 'wappalyzer']
    """
    try:
        results = {}
        total_steps = len(tools)
        current_step = 0
        
        socketio.emit('task_update', {'status': f'Starting Recon on {target}', 'percent': 1})
        
        if 'subfinder' in tools:
            current_step += 1
            socketio.emit('task_update', {'status': f'Running Subfinder ({current_step}/{total_steps})...', 'percent': int((current_step/total_steps)*30)})
            manager = ScanManager()
            
            subdomains = manager.run_subfinder(target)
            results['subdomains'] = subdomains
            
            # Save
            get_subdomains_collection().insert_one({
                "target": target, 
                "scan_id": self.request.id, 
                "subdomains": subdomains,
                "timestamp": datetime.datetime.utcnow()
            })
            
            # QoL: Emit intermediate result immediately
            socketio.emit('task_update', {
                'status': f'Subfinder finished. Found {len(subdomains)} subdomains.',
                'percent': int((current_step/total_steps)*30),
                'partial_result': {'subdomains': subdomains} 
            })
            
        if 'wafw00f' in tools:
            current_step += 1
            socketio.emit('task_update', {'status': f'Running WAF Detection ({current_step}/{total_steps})...', 'percent': int((current_step/total_steps)*45)})
            manager = ScanManager()
            waf_res = manager.run_wafw00f(target)
            results['waf'] = waf_res
            
            # Emit intermediate result
            socketio.emit('task_update', {
                'status': 'WAF Check complete.',
                'percent': int((current_step/total_steps)*45),
                'partial_result': {'waf': waf_res}
            })

        if 'nmap' in tools:
            current_step += 1
            socketio.emit('task_update', {'status': f'Running Nmap ({current_step}/{total_steps})...', 'percent': int((current_step/total_steps)*60)})
            manager = ScanManager()
            nmap_res = manager.run_nmap(target)
            results['nmap'] = nmap_res

            
            get_scans_collection().insert_one({
                "target": target,
                "scan_id": self.request.id,
                "type": "nmap",
                "results": nmap_res,
                "timestamp": datetime.datetime.utcnow()
            })
            
            socketio.emit('task_update', {
                'status': 'Nmap finished.',
                'percent': int((current_step/total_steps)*60),
                'partial_result': {'nmap': nmap_res} 
            })
            
        if 'wappalyzer' in tools:
            current_step += 1
            socketio.emit('task_update', {'status': f'Running Wappalyzer ({current_step}/{total_steps})...', 'percent': int((current_step/total_steps)*90)})
            manager = ScanManager()
            tech_res = manager.run_wappalyzer(target)
            results['technologies'] = tech_res
            
            for t in tech_res:
                get_technologies_collection().insert_one({
                    "target": target,
                    "scan_id": self.request.id,
                    "name": t,
                    "timestamp": datetime.datetime.utcnow()
                })

            socketio.emit('task_update', {
                'status': 'Tech Detect finished.',
                'percent': int((current_step/total_steps)*90),
                'partial_result': {'technologies': tech_res} 
            })

        socketio.emit('task_update', {
            'status': 'All scans completed successfully!',
            'percent': 100,
            'result': results  # Send full results to frontend to render
        })
        
        return {'status': 'COMPLETED', 'results': results}

    except Exception as e:
        socketio.emit('task_update', {'status': f'Error: {str(e)}', 'percent': 0})
        raise e

