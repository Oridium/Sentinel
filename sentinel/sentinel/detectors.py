"""Rolling-window brute-force detection and deterministic alert aggregation."""

import hashlib
import json
from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable

from .models import Alert, AuthEvent, DetectionConfig, Severity


def severity_for(peak_count: int, threshold: int) -> Severity:
    if peak_count >= threshold * 4:
        return "critical"
    if peak_count >= threshold * 2:
        return "high"
    return "medium"


def detect_brute_force(events: Iterable[AuthEvent], config: DetectionConfig) -> list[Alert]:
    """Merge overlapping qualifying windows per (destination host, source IP).

    Window endpoints are inclusive. Severity uses the peak window count, not
    the total count in a potentially long episode. Successes never add failures.
    """
    groups: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.outcome == "failure":
            groups[(event.host, event.source_ip)].append(event)
    alerts: list[Alert] = []
    duration = timedelta(seconds=config.window_seconds)
    for (host, source_ip), failures in groups.items():
        failures.sort(key=lambda event: (event.timestamp, event.source, event.line_number))
        window: deque[int] = deque()
        start: int | None = None
        end = peak = 0

        def finish(first: int, last: int, maximum: int) -> None:
            burst = failures[first:last + 1]
            identity = json.dumps([
                "ssh_brute_force", host, source_ip, burst[0].timestamp.isoformat(),
                burst[-1].timestamp.isoformat(), len(burst), maximum,
                config.threshold, config.window_seconds,
            ], separators=(",", ":"), ensure_ascii=True)
            # Stable identity only; this hash does not authenticate the evidence.
            alert_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
            alerts.append(Alert(
                alert_id=alert_id, rule="ssh_brute_force",
                severity=severity_for(maximum, config.threshold), host=host, source_ip=source_ip,
                first_seen=burst[0].timestamp, last_seen=burst[-1].timestamp,
                attempt_count=len(burst), peak_window_count=maximum,
                threshold=config.threshold, window_seconds=config.window_seconds,
                usernames=tuple(sorted({event.username for event in burst})),
                evidence=tuple((event.source, event.line_number) for event in burst[:10]),
            ))

        for index, event in enumerate(failures):
            while window and event.timestamp - failures[window[0]].timestamp > duration:
                window.popleft()
            window.append(index)
            if len(window) < config.threshold:
                continue
            if start is not None and failures[window[0]].timestamp > failures[end].timestamp:
                finish(start, end, peak)
                start = None
            if start is None:
                start, peak = window[0], 0
            end = index
            peak = max(peak, len(window))
        if start is not None:
            finish(start, end, peak)
    return sorted(alerts, key=lambda alert: (alert.first_seen, alert.host, alert.source_ip))

