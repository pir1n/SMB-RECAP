def safe_float(value, default=0):
    if value is None:
        return default

    try:
        return float(value)
    except Exception:
        return default


def build_timeline(events):
    return sorted(
        events,
        key=lambda x: (
            x.get("timestamp") is None,
            safe_float(x.get("timestamp")),
            x.get("frames", [0])[0] if x.get("frames") else 0,
        )
    )