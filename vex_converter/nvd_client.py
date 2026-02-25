"""
VDR 보강을 위한 NVD API 클라이언트
"""
from typing import Optional, Dict, List

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class NVDAPIClient:
    """
    취약점 메타데이터를 가져오기 위한 NVD API 2.0 클라이언트.
    속도 제한: 50 요청/30초 (공개), 5000 요청/30초 (API 키 사용 시)
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}

    def fetch_cve_data(self, cve_id: str) -> Optional[Dict]:
        """캐싱과 함께 NVD API에서 CVE 데이터 가져오기"""
        if cve_id in self.cache:
            cached_value = self.cache[cve_id]
            if cached_value is False:
                return None
            return cached_value

        if not REQUESTS_AVAILABLE:
            print("Warning: 'requests' library not installed. Install with: pip install requests")
            self.cache[cve_id] = False
            return None

        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            url = f"{self.base_url}?cveId={cve_id}"
            response = requests.get(url, headers=headers, timeout=5)

            if response.status_code == 200:
                data = response.json()
                self.cache[cve_id] = data
                return data
            elif response.status_code == 429:
                print(f"Warning: NVD API rate limit exceeded for {cve_id}")
                self.cache[cve_id] = False
                return None
            else:
                print(f"Warning: NVD API returned {response.status_code} for {cve_id}")
                self.cache[cve_id] = False
                return None
        except Exception as e:
            print(f"Warning: Failed to fetch {cve_id} from NVD: {e}")
            self.cache[cve_id] = False
            return None

    def extract_cwes(self, cve_data: Dict) -> List[Dict[str, str]]:
        """NVD 응답에서 CWE 정보 추출"""
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
        """NVD 응답에서 CVSS 점수 추출"""
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
                    "method": "CVSSv31",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString")
                })

            # CVSS v3.0
            for cvss_v3 in metrics.get("cvssMetricV30", []):
                cvss_data = cvss_v3.get("cvssData", {})
                ratings.append({
                    "method": "CVSSv30",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString")
                })

            # CVSS v2
            for cvss_v2 in metrics.get("cvssMetricV2", []):
                cvss_data = cvss_v2.get("cvssData", {})
                ratings.append({
                    "method": "CVSSv2",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_v2.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString")
                })
        except:
            pass

        return ratings

    def enrich_vulnerability(self, vuln) -> "Vulnerability":
        """NVD 데이터(CWE, CVSS)로 취약점 보강"""
        from .models import CvssRating
        
        if not vuln.id or not vuln.id.startswith("CVE-"):
            return vuln

        needs_cwes = not vuln.cwes or len(vuln.cwes) == 0
        needs_ratings = not vuln.ratings or len(vuln.ratings) == 0
        
        if not needs_cwes and not needs_ratings:
            return vuln

        cve_data = self.fetch_cve_data(vuln.id)
        if not cve_data:
            return vuln

        if needs_cwes:
            nvd_cwes = self.extract_cwes(cve_data)
            for cwe_info in nvd_cwes:
                if cwe_info["id"] not in vuln.cwes:
                    vuln.cwes.append(cwe_info["id"])

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