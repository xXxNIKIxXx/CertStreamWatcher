import re
from collections import Counter
import math

from services.shared.logger import get_logger

logger = get_logger(__name__)

def shannon_entropy(data):
    if not data:
        return 0.0
    p, lns = Counter(data), float(len(data))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

def levenshtein(a, b):
    if a == b:
        return 0
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class CertScoring:
    def __init__(self, keywords: dict, tlds: list, confusables: dict):
        self.keywords = keywords
        self.tlds = tlds
        self.confusables = confusables

    def unconfuse(self, domain):
        if domain.startswith('xn--'):
            try:
                domain = domain.encode('idna').decode('idna')
            except Exception:
                pass
        unconfused = ''
        for c in domain:
            unconfused += self.confusables.get(c, c)
        return unconfused

    def score_domain(self, domain):
        score = 0
        # TLD scoring
        for t in self.tlds:
            if domain.endswith(t):
                score += 20

        # Remove initial '*.' for wildcard certs
        if domain.startswith('*.'):
            domain = domain[2:]

        # Remove TLD to catch inner TLD in subdomain (e.g., paypal.com.domain.com)
        try:
            # If tld module is available, use it. Otherwise, fallback.
            from tld import get_tld
            res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
            domain = '.'.join([res.subdomain, res.domain])
        except Exception:
            pass

        # Entropy
        score += int(round(shannon_entropy(domain) * 10))

        # Remove confusables
        domain = self.unconfuse(domain)

        words_in_domain = re.split(r"\W+", domain)

        # Detect fake .com/net/org at start
        if words_in_domain and words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

        # Keyword scoring
        for word in self.keywords:
            if word in domain:
                score += self.keywords[word]

        # Levenshtein for strong keywords (>=70)
        for key, s in self.keywords.items():
            if s >= 70:
                for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
                    if levenshtein(str(word), str(key)) == 1:
                        score += 70

        # Lots of dashes
        if 'xn--' not in domain and domain.count('-') >= 4:
            score += domain.count('-') * 3

        # Deeply nested subdomains
        if domain.count('.') >= 3:
            score += domain.count('.') * 3

        return score

    def score(self, cert: dict) -> int:
        score = 0
        val = cert.get("dns_names", "")
        if isinstance(val, list):
            vals = val
        else:
            vals = [str(val)]
        for item in vals:
            score = max(score, self.score_domain(item))
        # If issued from a free CA = more suspicious
        issuer = cert.get("issuer", "")
        if isinstance(issuer, dict):
            org = issuer.get("O") or issuer.get("organizationName")
            if org and "let's encrypt" in org.lower():
                score += 10
        elif isinstance(issuer, str):
            if "let's encrypt" in issuer.lower():
                score += 10
        logger.debug(f"\n==== Total domain score: {score} ====")
        return score
