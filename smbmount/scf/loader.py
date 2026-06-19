import json
from pathlib import Path


def _normalize_rule(rule):
    """
    Chuẩn hóa rule JSON.
    Format mới:
    {
      "id": "delete_file",
      "action": "deletion of file",
      "pattern": ["hash1", "hash2", "hash3"],
      "require_success": true
    }
    """
    if "pattern" in rule:
        if not isinstance(rule["pattern"], list):
            raise ValueError(f"Rule {rule.get('id')} pattern must be a list")
        if not rule["pattern"]:
            raise ValueError(f"Rule {rule.get('id')} pattern is empty")

        return {
            "id": rule.get("id") or rule.get("action") or "unnamed_rule",
            "action": rule.get("action") or rule.get("id") or "unknown activity",
            "pattern": rule["pattern"],
            "require_success": bool(rule.get("require_success", False)),
            "description": rule.get("description"),
        }

    # Legacy rule: {"hash": "...", "action": "..."}
    if "hash" in rule:
        return {
            "id": rule.get("id") or rule.get("action") or "legacy_rule",
            "action": rule.get("action") or "unknown activity",
            "hash": rule["hash"],
            "require_success": bool(rule.get("require_success", False)),
            "description": rule.get("description"),
        }

    raise ValueError(f"Invalid rule: {rule}")


def _load_json_rules(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, dict):
        data = data.get("rules", [])

    if not isinstance(data, list):
        raise ValueError("JSON rule file must be a list or {'rules': [...]}")

    return [_normalize_rule(rule) for rule in data]


def _load_tsv_rules(path: Path):
    """
    Tương thích format cũ:
    hash<TAB>action

    Có hỗ trợ thêm format:
    id<TAB>action<TAB>hash1,hash2,hash3
    """
    rules = []

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split("\t")

            # legacy: hash<TAB>action
            if len(parts) == 2:
                rules.append(_normalize_rule({
                    "id": f"legacy_{line_no}",
                    "hash": parts[0],
                    "action": parts[1],
                }))
                continue

            # new TSV: id<TAB>action<TAB>hash1,hash2,hash3
            if len(parts) >= 3:
                pattern = [x.strip() for x in parts[2].split(",") if x.strip()]
                rules.append(_normalize_rule({
                    "id": parts[0],
                    "action": parts[1],
                    "pattern": pattern,
                }))
                continue

            raise ValueError(f"Invalid rule line {line_no}: {line}")

    return rules


def load_rules(rule_file):
    path = Path(rule_file)

    text = path.read_text(encoding="utf-8").lstrip()

    if path.suffix.lower() == ".json" or text.startswith("[") or text.startswith("{"):
        return _load_json_rules(path)

    return _load_tsv_rules(path)