from pathlib import Path
import re
import yaml
from typing import List, Dict, Any
class SigmaRule:
    def __init__(self, path: Path):
        with open(path) as f:
            data = yaml.safe_load(f)
        self.title = data.get("title", "")
        self.description = data.get("description", "")
        self.tags = data.get("tags", [])
        self.level = data.get("level", "medium")
        self.logsource = data.get("logsource", {})
        self.detection = data.get("detection", {})
        self.fields = data.get("fields", {})
        self.condition = data.get("condition", "selection")
    def evaluate(self, event: Dict[str, Any]) -> bool:
        detection = self.detection
        matches = {}
        for field, values in detection.items():
            if isinstance(values, list):
                field_matches = any(self._match_value(v, event.get(field, "")) for v in values)
            else:
                field_matches = self._match_value(values, event.get(field, ""))
            matches[field] = field_matches
        return self._evaluate_condition(self.condition, matches)
    def _match_value(self, pattern: str, value: str) -> bool:
        if isinstance(pattern, str):
            if pattern.startswith("*") or pattern.endswith("*"):
                return pattern.replace("*", "").lower() in value.lower()
            return pattern.lower() in value.lower()
        return False
    def _evaluate_condition(self, condition: str, matches: Dict[str, bool]) -> bool:
        expr = condition
        for name, match in matches.items():
            expr = expr.replace(name, str(match))
        expr = expr.replace("1 of them", str(any(matches.values())))
        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))
        except:
            return any(matches.values())
def run_sigma_on_text(text: str, rules_dir: Path) -> List[Dict[str, Any]]:
    hits = []
    sdir = rules_dir / "sigma"
    for p in sdir.glob("*.yml"):
        try:
            rule = SigmaRule(p)
            if rule.evaluate({"CommandLine": text}):
                hits.append({"title": rule.title, "description": rule.description, "level": rule.level, "tags": rule.tags})
        except Exception:
            pass
    return hits
