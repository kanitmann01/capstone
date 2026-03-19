from scanner.normalization import NormalizedTarget


class URLHeuristics:
    def __init__(self, target: NormalizedTarget):
        self.target = target

    def check_ip_address(self) -> bool:
        return self.target.is_ip

    def check_url_length(self, threshold: int = 80) -> bool:
        return len(self.target.normalized_url) > threshold

    def check_suspicious_chars(self) -> bool:
        if "@" in self.target.normalized_url:
            return True
        if self.target.host.count(".") > 4:
            return True
        return False

    def check_keyword_masking(self) -> bool:
        suspicious_keywords = {
            "paypal",
            "apple",
            "google",
            "microsoft",
            "facebook",
            "amazon",
            "bank",
            "login",
            "signin",
            "verify",
            "secure",
        }
        host = self.target.host.lower()
        full_url = self.target.normalized_url.lower()
        for keyword in suspicious_keywords:
            if keyword not in full_url:
                continue
            if keyword not in host:
                return True
            if keyword in self.target.path.lower() or keyword in self.target.query.lower():
                return True
        return False

    def run_checks(self) -> dict:
        is_ip_address = self.check_ip_address()
        excessive_length = self.check_url_length()
        suspicious_chars = self.check_suspicious_chars()
        keyword_masking = self.check_keyword_masking()

        score = 0
        if is_ip_address:
            score += 30
        if excessive_length:
            score += 10
        if suspicious_chars:
            score += 20
        if keyword_masking:
            score += 25

        return {
            "status": "ok",
            "is_ip_address": is_ip_address,
            "excessive_length": excessive_length,
            "suspicious_chars": suspicious_chars,
            "keyword_masking": keyword_masking,
            "risk_score": min(score, 100),
        }
