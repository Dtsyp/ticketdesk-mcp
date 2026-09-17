import json
import re
from pathlib import Path


class TicketStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.tickets_dir = self.root / "tickets"
        self.attachments_dir = self.root / "attachments"

    def get(self, ticket_id: str):
        path = self.tickets_dir / f"{ticket_id}.json"
        if not path.exists():
            return None
        with open(path) as f:
            return json.load(f)

    def search(self, query: str, status=None, assignee=None):
        results = []
        pattern = re.compile(query)
        for p in self.tickets_dir.glob("*.json"):
            with open(p) as f:
                t = json.load(f)
            if status and t.get("status") != status:
                continue
            if assignee and t.get("assignee") != assignee:
                continue
            haystack = t.get("subject", "") + " " + " ".join(
                c.get("body", "") for c in t.get("comments", [])
            )
            if pattern.search(haystack):
                results.append(t)
        return results

    def add_comment(self, ticket_id: str, author: str, body: str):
        path = self.tickets_dir / f"{ticket_id}.json"
        with open(path) as f:
            t = json.load(f)
        t.setdefault("comments", []).append({"author": author, "body": body})
        with open(path, "w") as f:
            json.dump(t, f, indent=2, ensure_ascii=False)
        return t

    def close(self, ticket_id: str, reason: str):
        path = self.tickets_dir / f"{ticket_id}.json"
        with open(path) as f:
            t = json.load(f)
        t["status"] = "closed"
        t["close_reason"] = reason
        with open(path, "w") as f:
            json.dump(t, f, indent=2, ensure_ascii=False)
        return t

    def read_attachment(self, ticket_id: str, filename: str) -> str:
        path = self.attachments_dir / ticket_id / filename
        return path.read_text(errors="replace")
