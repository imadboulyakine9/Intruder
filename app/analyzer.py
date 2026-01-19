from app.db import get_technologies_collection, get_subdomains_collection, get_attackable_urls_collection

class Analyzer:
    """
    Analysis Engine for Intruder.
    Analyzes scan results to suggest appropriate attack tools.
    """

    def __init__(self):
        self.tech_col = get_technologies_collection()
        self.sub_col = get_subdomains_collection()
        self.atk_col = get_attackable_urls_collection()

    def analyze_target(self, target):
        """
        Analyze the target's scan data to generate tool suggestions.
        """
        suggestions = []
        
        # Fetch data
        technologies = self.get_technologies(target)
        urls = self.get_urls(target)
        attackable = self.get_attackable_urls(target)

        # Rule 3: Always suggest Nuclei
        suggestions.append({
            "tool": "Nuclei",
            "reason": "General vulnerability scanning for all targets."
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
             
             suggestions.append({
                "tool": "SQLMap",
                "reason": reason,
                "evidence": examples, # List of specific URLs
                "target_urls": attackable # Full list for the attack engine
            })
        elif any("?" in url for url in urls):
            suspicious_urls = [u for u in urls if "?" in u]
            examples = suspicious_urls[:3]
            suggestions.append({
                "tool": "SQLMap",
                "reason": "URLs with parameters ('?') detected in subdomains lookup.",
                "evidence": examples
            })
            
        # Additional Rule: Commix (Command Injection)
        suspect_params = ["cmd=", "exec=", "command=", "execute=", "ping=", "query=", "search=", "id="]
        commix_candidates = []
        for url in attackable:
             if any(param in url for param in suspect_params):
                 commix_candidates.append(url)
                 
        if commix_candidates:
             suggestions.append({
                "tool": "Commix",
                "reason": "Suspicious parameters detected (cmd/exec/id). Potential Command Injection.",
                "evidence": commix_candidates[:3]
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
