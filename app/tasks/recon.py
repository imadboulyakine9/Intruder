from app.celery_worker import celery_app, socketio
from app.scan_manager import ScanManager
from app.db import get_subdomains_collection, get_scans_collection, get_technologies_collection, get_vulnerabilities_collection, get_assets_collection
import datetime
import os
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
    Orchestrator task with Smart Filtering and WAF awareness.
    """
    try:
        results = {}
        total_steps = len(tools) # Approximate
        current_step = 0
        manager = ScanManager()
        is_protected = False
        scan_id = self.request.id
        
        # Create Master Scan Record
        get_scans_collection().insert_one({
            "target": target,
            "scan_id": scan_id,
            "type": "master",
            "status": "scanning",
            "timestamp": datetime.datetime.utcnow(),
            "tools": tools
        })
        
        socketio.emit('task_update', {'status': f'Starting Smart Recon on {target}', 'percent': 1})

        # 1. WAF Check (Priority)
        if 'wafw00f' in tools:
            current_step += 1
            socketio.emit('task_update', {'status': 'Checking for WAF...', 'percent': 10})
            waf_res = manager.run_wafw00f(target)
            results['waf'] = waf_res
            
            # Simple heuristic for protection
            waf_str = str(waf_res).lower()
            if 'cloudflare' in waf_str or 'akamai' in waf_str or 'imperva' in waf_str:
                is_protected = True
                socketio.emit('task_update', {'status': f'⚠️ WAF Detected ({waf_res}). Adjusting scan intensity.', 'percent': 15})
            
            # Emit intermediate result
            socketio.emit('task_update', {
                'status': 'WAF Check complete.', 
                'percent': 15, 
                'partial_result': {'waf': waf_res}
            })

        # 2. Subdomain & Smart Filter
        live_assets = []
        if 'subfinder' in tools:
            current_step += 1
            socketio.emit('task_update', {'status': 'Enumerating Subdomains...', 'percent': 20})
            
            subdomains = manager.run_subfinder(target)
            results['subdomains'] = subdomains
            
            # Smart Filter (httpx)
            socketio.emit('task_update', {'status': f'Found {len(subdomains)} candidates. Verifying live assets...', 'percent': 40})
            
            # Construct path to subfinder output for httpx
            sub_file = os.path.join(manager.output_dir, f"{target}_subdomains.txt")
            live_assets = manager.run_httpx(sub_file)
            
            results['live_assets'] = live_assets
            
            # Save Raw Subdomains
            get_subdomains_collection().insert_one({
                "target": target, 
                "scan_id": self.request.id, 
                "subdomains": subdomains, 
                "timestamp": datetime.datetime.utcnow()
            })
            
            # Save Live Assets (Asset-Centric)
            assets_col = get_assets_collection()
            for asset in live_assets:
                # asset is a dict from httpx json
                # Ensure we have a domain field, httpx gives 'input' or 'url'
                domain = asset.get('input', asset.get('url', ''))
                if domain:
                     assets_col.update_one(
                         {"domain": domain}, 
                         {"$set": {
                             "parent_domain": target, 
                             "last_seen": datetime.datetime.utcnow(),
                             "ip": asset.get('host'),
                             "tech": asset.get('tech', []), # httpx sometimes has tech
                             "status_code": asset.get('status_code')
                         }}, 
                         upsert=True
                     )

            socketio.emit('task_update', {
                'status': f'Smart Filter: {len(live_assets)} live assets identified from {len(subdomains)} subdomains.',
                'percent': 50,
                'partial_result': {'subdomains': subdomains, 'live_assets': live_assets} 
            })

        # 3. Nmap (WAF Aware)
        if 'nmap' in tools:
            current_step += 1
            if is_protected:
                socketio.emit('task_update', {'status': 'Skipping aggressive Nmap on main target due to WAF.', 'percent': 60})
                # Return a dummy object that matches the frontend's expected schema
                results['nmap'] = [{
                    "port": "WAF",
                    "protocol": "BLOCK", 
                    "service": "Aggressive Scan Skipped"
                }]
            else:
                socketio.emit('task_update', {'status': 'Running Nmap on main target...', 'percent': 60})
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
                    'percent': 70,
                    'partial_result': {'nmap': nmap_res} 
                })
            
        # 4. Tech Detection (Wappalyzer)
        if 'wappalyzer' in tools:
            current_step += 1
            socketio.emit('task_update', {'status': 'Analyzing Technologies...', 'percent': 90})
            
            # IMPROVEMENT: Use live assets if available, otherwise fallback to target
            targets_to_scan = [target]
            if 'live_assets' in results and results['live_assets']:
                # extracting URLs from live_assets
                # live_assets is a list of dicts from httpx
                targets_to_scan = [asset.get('url', asset.get('input')) for asset in results['live_assets']]
                # Limit to top 3 to save time/resources if list is huge
                targets_to_scan = targets_to_scan[:3] 
                if target not in targets_to_scan:
                    targets_to_scan.insert(0, target)
            
            all_tech = set()
            for t_url in targets_to_scan:
                if not t_url: continue
                try:
                    t_res = manager.run_wappalyzer(t_url)
                    all_tech.update(t_res)
                except:
                    pass
            
            tech_res = list(all_tech)
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
                'percent': 100,
                'partial_result': {'technologies': tech_res} 
            })

        socketio.emit('task_update', {
            'status': 'All scans completed successfully!',
            'percent': 100,
            'result': results
        })
        
        # Update Master Scan Record
        get_scans_collection().update_one(
            {"scan_id": scan_id, "type": "master"},
            {"$set": {"status": "scanned", "results_summary": results}}
        )
        
        return {'status': 'COMPLETED', 'results': results}

    except Exception as e:
        socketio.emit('task_update', {'status': f'Error: {str(e)}', 'percent': 0})
        # Update Master Scan Record on Failure
        try:
             get_scans_collection().update_one(
                {"scan_id": self.request.id, "type": "master"},
                {"$set": {"status": "failed", "error": str(e)}}
            )
        except:
            pass
        raise e

