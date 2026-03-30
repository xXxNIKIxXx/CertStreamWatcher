import yaml
import os

from .confusables import confusables


def _load_scoring_config():
    base_path = os.path.dirname(__file__)
    suspicious_path = os.path.abspath(os.path.join(base_path, "..", "configs", "suspicious.yaml"))
    external_path = os.path.abspath(os.path.join(base_path, "..", "configs", "external.yaml"))
    config = {}
    suspicious = {}
    external = {}

    # Load suspicious.yaml
    if os.path.exists(suspicious_path):
        with open(suspicious_path, "r") as f:
            suspicious = yaml.safe_load(f) or {}

    # Load external.yaml
    if os.path.exists(external_path):
        with open(external_path, "r") as f:
            external = yaml.safe_load(f) or {}

    if external.pop("override_suspicious.yaml", False):
        config = external
    else:
        config = {**suspicious, **external}

        for k in ["keywords", "tlds"]:
            if k in suspicious and k in external:
                if isinstance(suspicious[k], dict) and isinstance(external[k], dict):
                    merged = {**suspicious[k], **external[k]}
                    config[k] = merged
                elif isinstance(suspicious[k], list) and isinstance(external[k], list):
                    config[k] = list(set(suspicious[k] + external[k]))

    config["confusables"] = confusables
    return config
