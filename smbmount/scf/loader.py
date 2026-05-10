from pathlib import Path


def load_rules(rule_file):

    rules = []

    path = Path(rule_file)

    with path.open("r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            #
            # format:
            # hash<TAB>action
            #
            parts = line.split("\t")

            if len(parts) != 2:
                continue

            rules.append({
                "hash": parts[0],
                "action": parts[1],
            })

    return rules