import json
from datetime import datetime, timezone


def create_event(source, event_type, src_ip, **details):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "event_type": event_type,
        "src_ip": src_ip,
        "details": details,
    }


def load_events(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
