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
        Returns a sorted list of ALL tools with suitability scores (0-100).
        """
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

        results = []
        
        # --- DEFINE ALL TOOLS ---
        # Each tool starts with a base score (usually 10% just for existing)
        # We then boost or nerf based on Rules.
        
        # 1. Nuclei (General Scanner)
        # Base: 80% (Always recommended)
        nuclei_score = 80
        nuclei_reason = "Standard vulnerability scanning."
        if waf_detected:
            nuclei_score = 60
            nuclei_reason += f" (WAF {waf_name} Active - Rate Limit Recommended)."
        
        results.append({
            "tool": "Nuclei",
            "score": nuclei_score,
            "reason": nuclei_reason,
            "specific_targets": []
        })

        # 2. SQLMap (SQL Injection)
        # Base: 10% (Don't run blindly)
        sqlmap_score = 10
        sqlmap_reason = "No obvious parameters found."
        sqlmap_targets = []
        
        if attackable:
            sqlmap_score = 90
            count = len(attackable)
            sqlmap_reason = f"Highly Recommended. Found {count} URL parameters."
            sqlmap_targets = attackable
        elif any("?" in url for url in urls):
            sqlmap_score = 50
            sqlmap_reason = "Possible parameters detected in subdomains."
            sqlmap_targets = [u for u in urls if "?" in u]
        
        if waf_detected and sqlmap_score > 30:
            sqlmap_score -= 20
            sqlmap_reason += " (WAF Active: Tamper scripts required)."

        results.append({
            "tool": "SQLMap",
            "score": sqlmap_score,
            "reason": sqlmap_reason,
            "specific_targets": sqlmap_targets[:20] if sqlmap_targets else [], # Limit list size
            "evidence": sqlmap_targets[:3]
        })

        # 3. WPScan (WordPress)
        wpscan_score = 5
        wpscan_reason = "No WordPress detected."
        if "WordPress" in technologies:
            wpscan_score = 95
            wpscan_reason = "WordPress Technology Detected."
        
        results.append({
            "tool": "WPScan",
            "score": wpscan_score,
            "reason": wpscan_reason,
            "specific_targets": []
        })

        # 4. Dalfox (XSS)
        dalfox_score = 10
        dalfox_reason = "No parameters found."
        dalfox_targets = []

        if attackable:
            dalfox_score = 85
            dalfox_reason = f"Recommended. {len(attackable)} URLs with parameters."
            dalfox_targets = attackable
        elif any("?" in url for url in urls):
            dalfox_score = 40
            dalfox_reason = "Parameters likely present."
            dalfox_targets = [u for u in urls if "?" in u]
        
        if waf_detected and dalfox_score > 30:
            dalfox_score -= 10
            dalfox_reason += " (WAF might block XSS payloads)."

        results.append({
            "tool": "Dalfox",
            "score": dalfox_score,
            "reason": dalfox_reason,
            "specific_targets": dalfox_targets[:20] if dalfox_targets else [],
            "evidence": dalfox_targets[:3]
        })
        
        # 5. Commix (Command Injection)
        commix_score = 5
        commix_reason = "No suspicious command parameters."
        commix_targets = []
        suspect_params = ["cmd=", "exec=", "command=", "execute=", "ping=", "query=", "search=", "id="]
        
        found_commix = []
        if attackable:
            for url in attackable:
                if any(p in url for p in suspect_params):
                    found_commix.append(url)
        
        if found_commix:
            commix_score = 75
            commix_reason = "Suspicious parameters (cmd/exec) found."
            commix_targets = found_commix
        
        results.append({
             "tool": "Commix",
             "score": commix_score,
             "reason": commix_reason,
             "specific_targets": commix_targets[:10]
        })

        # 6. Nikto (Web Server)
        nikto_score = 40
        nikto_reason = "Comprehensive web server scanner (6700+ checks)."
        if waf_detected:
            nikto_score = 10
            nikto_reason = "WAF detected (Nikto is noisy)."
        else:
            nikto_score = 70
            # Keep the detailed reason if score is high, or append it?
            # User specifically asked for the description. 
            # I will prepend it to the reason or just use it. 
            # "Comprehensive web server scanner (6700+ checks)."
            pass

        results.append({
            "tool": "Nikto",
            "score": nikto_score,
            "reason": nikto_reason,
            "specific_targets": []
        })

        # Sort by score (Highest first)
        return sorted(results, key=lambda x: x['score'], reverse=True)

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
