"""
NVD API Client
"""
import json
import time
from typing import Optional, Dict, Any, List

from vex_converter.models import CvssRating
try:
    from urllib import request, error
except:
    import urllib.request as request
    import urllib.error as error

class NVDAPIClient:
    """
    Client for NVD API 2.0 to fetch vulnerability metadata.
    Rate limits: 50 requests/30s (public), 5000 requests/30s (with API key)
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}  # Simple in-memory cache

    def fetch_cve_data(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE data from NVD API with caching"""
        # Check cache (including failed attempts marked as False)
        if cve_id in self.cache:
            cached_value = self.cache[cve_id]
            if cached_value is False:
                # Previously failed - don't retry
                return None
            return cached_value

        try:
            import requests
            import time

            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            url = f"{self.base_url}?cveId={cve_id}"
            response = requests.get(url, headers=headers, timeout=5)  # Reduced from 10s to 5s

            if response.status_code == 200:
                data = response.json()
                self.cache[cve_id] = data
                return data
            elif response.status_code == 429:
                # Rate limit exceeded - cache failure
                print(f"Warning: NVD API rate limit exceeded for {cve_id}")
                self.cache[cve_id] = False  # Mark as failed
                return None
            else:
                print(f"Warning: NVD API returned {response.status_code} for {cve_id}")
                self.cache[cve_id] = False  # Mark as failed
                return None
        except ImportError:
            print("Warning: 'requests' library not installed. Install with: pip install requests")
            self.cache[cve_id] = False  # Mark as failed
            return None
        except Exception as e:
            print(f"Warning: Failed to fetch {cve_id} from NVD: {e}")
            self.cache[cve_id] = False  # Mark as failed to prevent retries
            return None

    def extract_cwes(self, cve_data: Dict) -> List[Dict[str, str]]:
        """Extract CWE information from NVD response"""
        cwes = []
        try:
            vulnerabilities = cve_data.get("vulnerabilities", [])
            if not vulnerabilities:
                return cwes

            cve = vulnerabilities[0].get("cve", {})
            weaknesses = cve.get("weaknesses", [])

            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwe_id = cwe_value.replace("CWE-", "")
                        try:
                            cwes.append({
                                "id": int(cwe_id),
                                "name": desc.get("lang", "en")
                            })
                        except ValueError:
                            pass
        except:
            pass

        return cwes

    def extract_cvss(self, cve_data: Dict) -> List[Dict]:
        """Extract CVSS scores from NVD response"""
        ratings = []
        try:
            vulnerabilities = cve_data.get("vulnerabilities", [])
            if not vulnerabilities:
                return ratings

            cve = vulnerabilities[0].get("cve", {})
            metrics = cve.get("metrics", {})

            # CVSS v3.1
            for cvss_v3 in metrics.get("cvssMetricV31", []):
                cvss_data = cvss_v3.get("cvssData", {})
                ratings.append({
                    "method": "CVSSv3.1",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString", "").replace("CVSS:3.1/", "")
                })

            # CVSS v3.0
            for cvss_v3 in metrics.get("cvssMetricV30", []):
                cvss_data = cvss_v3.get("cvssData", {})
                ratings.append({
                    "method": "CVSSv3.0",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString", "").replace("CVSS:3.0/", "")
                })

            # CVSS v2
            for cvss_v2 in metrics.get("cvssMetricV2", []):
                cvss_data = cvss_v2.get("cvssData", {})
                ratings.append({
                    "method": "CVSSv2",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_v2.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString", "").replace("CVSS:2.0/", "")
                })
        except:
            pass

        return ratings

    def enrich_vulnerability(self, vuln: "Vulnerability") -> "Vulnerability":
        """Enrich vulnerability with NVD data (CWE, CVSS)"""
        if not vuln.id.startswith("CVE-"):
            return vuln

        # Check if enrichment is actually needed
        needs_cwes = not vuln.cwes or len(vuln.cwes) == 0
        needs_ratings = not vuln.ratings or len(vuln.ratings) == 0
        
        if not needs_cwes and not needs_ratings:
            # Already has all data - skip NVD API call
            return vuln

        # Only fetch from NVD if we need data
        cve_data = self.fetch_cve_data(vuln.id)
        if not cve_data:
            return vuln

        # Add CWEs if missing
        if needs_cwes:
            nvd_cwes = self.extract_cwes(cve_data)
            for cwe_info in nvd_cwes:
                if cwe_info["id"] not in vuln.cwes:
                    vuln.cwes.append(cwe_info["id"])

        # Add CVSS ratings if missing
        if needs_ratings:
            nvd_ratings = self.extract_cvss(cve_data)
            for rating_data in nvd_ratings:
                vuln.ratings.append(CvssRating(
                    method=rating_data["method"],
                    score=rating_data.get("score"),
                    severity=rating_data.get("severity"),
                    vector=rating_data.get("vector")
                ))

        return vuln

# ===== DATA MODEL =====