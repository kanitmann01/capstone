import requests
from bs4 import BeautifulSoup
from scanner.normalization import NormalizedTarget
from scanner.settings import ScannerSettings

class ContentScanner:
    def __init__(self, target: NormalizedTarget, settings: ScannerSettings):
        self.target = target
        self.settings = settings
        self.html_content = ""
        self.soup = None
        self.last_error = ""

    def fetch_content(self) -> bool:
        """Fetch the HTML content of the page."""
        try:
            response = requests.get(
                self.target.normalized_url,
                timeout=self.settings.request_timeout_seconds,
            )
            if response.status_code == 200:
                self.html_content = response.text
                self.soup = BeautifulSoup(self.html_content, 'html.parser')
                return True
            self.last_error = f"status_code={response.status_code}"
        except Exception as exc:
            self.last_error = str(exc)
            return False
        return False

    def check_password_field(self) -> bool:
        """Check if there is a password input field on a non-HTTPS page."""
        if not self.soup:
            return False
            
        password_inputs = self.soup.find_all('input', {'type': 'password'})
        if password_inputs and self.target.scheme != 'https':
            return True
        return False

    def check_suspicious_keywords(self) -> bool:
        """Check for suspicious keywords in the page text."""
        if not self.soup:
            return False
            
        text = self.soup.get_text().lower()
        keywords = ["verify account", "urgent action required", "security alert", "confirm your identity", "update payment"]
        
        for keyword in keywords:
            if keyword in text:
                return True
        return False

    def check_hidden_elements(self) -> bool:
        """Check for hidden iframes or elements (basic check)."""
        if not self.soup:
            return False
            
        # Check for iframes with 0 size or hidden style
        iframes = self.soup.find_all('iframe')
        for iframe in iframes:
            width = iframe.get('width', '100')
            height = iframe.get('height', '100')
            style = iframe.get('style', '')
            
            if width == '0' or height == '0' or 'display: none' in style or 'visibility: hidden' in style:
                return True
                
        return False

    def run_checks(self) -> dict:
        fetched = self.fetch_content()
        
        if not fetched:
            return {
                "status": "unknown",
                "unknown_reason": "content_unavailable",
                "error": self.last_error,
                "content_fetched": False,
                "password_on_http": False,
                "suspicious_keywords": False,
                "hidden_elements": False,
                "risk_score": 0,
            }

        password_http = self.check_password_field()
        keywords = self.check_suspicious_keywords()
        hidden = self.check_hidden_elements()
        
        score = 0
        if password_http: score += 80 # Very high risk
        if keywords: score += 30
        if hidden: score += 20
        
        return {
            "status": "ok",
            "content_fetched": True,
            "password_on_http": password_http,
            "suspicious_keywords": keywords,
            "hidden_elements": hidden,
            "risk_score": min(score, 100),
        }
