def build_timeline(events):

    return sorted(
        events,
        key=lambda x: x["timestamp"]
    )