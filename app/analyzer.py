from app.db import get_technologies_collection, get_subdomains_collection, get_attackable_urls_collection, get_scans_collection

class Analyzer:
    """
    Analysis Engine for Intruder.
    Analyzes scan results to suggest appropriate attack tools.
    """

    def __init__(self):
        self.tech_col = get_technologies_collection()
        self.sub_col = get_subdomains_collection()
        self.atk_col = get_attackable_urls_collection()
        self.scans_col = get_scans_collection()

    def analyze_target(self, target, scan_id=None):
        """
        Analyze the target's scan data to generate tool suggestions.
        """
        suggestions = []
        
        # 1. Fetch Context Data
        technologies = self.get_technologies(target)
        urls = self.get_urls(target)
        attackable = self.get_attackable_urls(target)
        
        # Check for WAF context
        waf_detected = False
        waf_name = "Unknown WAF"
        if scan_id:
            scan = self.scans_col.find_one({"scan_id": scan_id})
            if scan and 'results_summary' in scan:
                 waf_res = scan['results_summary'].get('waf', [])
                 if waf_res:
                     waf_detected = True
                     # Handle different WAF output formats (list of dicts or list of strings)
                     if isinstance(waf_res, list) and len(waf_res) > 0:
                         first_waf = waf_res[0]
                         if isinstance(first_waf, dict):
                             waf_name = first_waf.get('waf', waf_name)
                         else:
                             waf_name = str(first_waf)

        # --- INTELLIGENCE RULES ---

        # Rule 0: WAF Awareness (High Priority Info)
        if waf_detected:
             suggestions.append({
                "tool": "WAF Check", # Not an attack tool, but an insight
                "reason": f"Active Defense Detected: {waf_name}.", 
                "evidence": ["All subsequent attacks may require bypass techniques (tamper scripts).", "Rate limiting is likely."],
                "type": "warning" # Frontend can style this yellow
            })

        # Rule 3: Always suggest Nuclei (Adjusted for WAF)
        nuclei_reason = "General vulnerability scanning."
        if waf_detected:
            nuclei_reason += " (Recommendation: Run with -rate-limit 10 to avoid blocking)."
            
        suggestions.append({
            "tool": "Nuclei",
            "reason": nuclei_reason
        })

        # Rule 1: WordPress Detection
        if "WordPress" in technologies:
            suggestions.append({
                "tool": "WPScan",
                "reason": "WordPress detected. perform specialized WP enumeration."
            })

        # Rule 2: SQL Injection Parameter Detection
        # Check if any URL contains '?' indicating parameters
        # Use the specialized crawled list first
        if attackable:
             # Extract top 3 examples for display
             examples = attackable[:3]
             count = len(attackable)
             reason = f"High probability of SQLi/XSS. Found {count} URLs with parameters."
             
             if waf_detected:
                 reason = f"Possible SQLi Surface ({count} URLs), but {waf_name} is active. Success probability: LOW."
             
             suggestions.append({
                "tool": "SQLMap",
                "reason": reason,
                "evidence": examples, # List of specific URLs
                "target_urls": attackable # Full list for the attack engine
            })
        elif any("?" in url for url in urls):
            suspicious_urls = [u for u in urls if "?" in u]
            examples = suspicious_urls[:3]
            reason = "URLs with parameters ('?') detected in subdomains lookup."
            if waf_detected:
                reason += " Note: WAF is active."
                
            suggestions.append({
                "tool": "SQLMap",
                "reason": reason,
                "evidence": examples
            })
            
        # Additional Rule: Commix (Command Injection)
        suspect_params = ["cmd=", "exec=", "command=", "execute=", "ping=", "query=", "search=", "id="]
        commix_candidates = []
        for url in attackable:
             if any(param in url for param in suspect_params):
                 commix_candidates.append(url)
                 
        if str(commix_candidates): # Ensure it is truthy if not empty list
             suggestions.append({
                "tool": "Commix",
                "reason": "Suspicious parameters detected (cmd/exec/id). Potential Command Injection.",
                "evidence": commix_candidates[:3]
            })

        # Rule 4: Dalfox (XSS) - Suggest if parameters are found
        # Dalfox is great for XSS on parameters
        if attackable or any("?" in url for url in urls):
            evidence = attackable[:3] if attackable else [u for u in urls if "?" in u][:3]
            count = len(attackable) if attackable else len([u for u in urls if "?" in u])
            
            dalfox_reason = f"XSS Scanning recommended. Found {count} URLs with parameters."
            if waf_detected:
                dalfox_reason += " (WAF Active: XSS payloads might be blocked)."
                
            suggestions.append({
                "tool": "Dalfox",
                "reason": dalfox_reason, 
                "evidence": evidence,
                "target_urls": attackable # Analyzer passes this for context, though frontend uses ID/Tool
            })

        return suggestions

    def get_technologies(self, target):
        """Retrieve unique technologies for the target."""
        cursor = self.tech_col.find({"target": target})
        return list(set(doc["name"] for doc in cursor if "name" in doc))
        
    def get_attackable_urls(self, target):
        """Retrieve crawled URLs with parameters."""
        cursor = self.atk_col.find({"target": target})
        return [doc["url"] for doc in cursor if "url" in doc]

    def get_urls(self, target):
        """
        Retrieve all discovered URLs/Subdomains for the target.
        For now, this treats subdomains as potential URLs.
        In later phases, this should include crawled URLs from Katana/Hakrawler.
        """
        # Get subdomains
        sub_cursor = self.sub_col.find({"target": target})
        urls = []
        for doc in sub_cursor:
            if "subdomains" in doc:
                urls.extend(doc["subdomains"])
            if "url" in doc: # Future proofing if we store crawled URLs here
                urls.append(doc["url"])
        
        # Also check if we have a specific 'urls' collection or 'crawled_urls' later
        # For now, we assume subdomains are the main source, and we might check
        # if the target itself has parameters if it was passed as a full URL.
        # But 'target' is usually a domain.
        
        # If the user input 'target' is a URL with params, include it.
        if "?" in target:
            urls.append(target)
            
        return urls
