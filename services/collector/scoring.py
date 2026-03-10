class CertScoring:
    def __init__(self, keywords: dict, tlds: list, confusables: dict):
        self.keywords = keywords
        self.tlds = tlds
        self.confusables = confusables

    def score(self, cert: dict) -> int:
        score = 0
        for field in ["subject", "issuer", "dns_names"]:
            val = cert.get(field, "")
            if isinstance(val, list):
                vals = val
            else:
                vals = [str(val)]
            for item in vals:
                for kw, kw_score in self.keywords.items():
                    if kw.lower() in item.lower():
                        score += kw_score
                for tld in self.tlds:
                    if item.lower().endswith(tld):
                        score += 50
                for uni, rep in self.confusables.items():
                    if uni in item:
                        score += 10
        return score
