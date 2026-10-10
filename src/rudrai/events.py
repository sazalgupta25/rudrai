from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
from .output import atomic_write


@dataclass(slots=True)
class EventSink:
    events: list[dict[str, Any]] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    limit: int = 100000

    def emit(self, event_type: str, **payload: Any) -> None:
        if len(self.events) >= self.limit:
            raise ValueError("audit event budget exceeded")
        self.events.append(
            {
                "type": event_type,
                "schema_version": "1.1.0",
                "scan_id": self.scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                **payload,
            }
        )

    def write(self, path: Path) -> None:
        atomic_write(path, ("".join(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n" for event in self.events)).encode("utf-8"))

