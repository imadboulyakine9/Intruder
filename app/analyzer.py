from app.db import get_technologies_collection, get_subdomains_collection

class Analyzer:
    """
    Analysis Engine for Intruder.
    Analyzes scan results to suggest appropriate attack tools.
    """

    def __init__(self):
        self.tech_col = get_technologies_collection()
        self.sub_col = get_subdomains_collection()

    def analyze_target(self, target):
        """
        Analyze the target's scan data to generate tool suggestions.
        """
        suggestions = []
        
        # Fetch data
        technologies = self.get_technologies(target)
        urls = self.get_urls(target)

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
        has_params = any("?" in url for url in urls)
        if has_params:
            suggestions.append({
                "tool": "SQLMap",
                "reason": "URLs with parameters ('?') detected. Potential SQL Injection points."
            })

        return suggestions

    def get_technologies(self, target):
        """Retrieve unique technologies for the target."""
        cursor = self.tech_col.find({"target": target})
        return list(set(doc["name"] for doc in cursor if "name" in doc))

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
