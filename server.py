import json
import logging
import os
from contextvars import ContextVar
from pathlib import Path

from fastapi import FastAPI, Request
from mcp.server.fastmcp import FastMCP

from auth import verify_token
from storage import TicketStore

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ticketdesk")

DATA_DIR = Path(os.environ.get("TICKETDESK_DATA", "./data"))
store = TicketStore(DATA_DIR)

mcp = FastMCP("ticketdesk")

_current_user: ContextVar[dict | None] = ContextVar("current_user", default=None)


def get_current_user() -> dict:
    if os.environ.get("TICKETDESK_USER"):
        return {
            "username": os.environ["TICKETDESK_USER"],
            "groups": os.environ.get("TICKETDESK_GROUPS", "").split(","),
            "roles": ["employee"],
            "scopes": ["tickets:read", "tickets:write"],
        }
    return _current_user.get() or {
        "username": "anonymous",
        "groups": [],
        "roles": [],
        "scopes": [],
    }


def _can_read(user: dict, ticket: dict) -> bool:
    if "support" in user.get("roles", []):
        return True
    if user.get("username") == ticket.get("owner"):
        return True
    return bool(set(user.get("groups", [])) & set(ticket.get("groups", [])))


def _can_write(user: dict, ticket: dict) -> bool:
    if "support" in user.get("roles", []):
        return True
    return user.get("username") == ticket.get("owner")


@mcp.tool()
def search_tickets(query: str, status: str | None = None, assignee: str | None = None) -> list:
    """Search tickets by free-text query."""
    return store.search(query, status, assignee)


@mcp.tool()
def get_ticket(ticket_id: str) -> dict:
    """Fetch a single ticket by id."""
    user = get_current_user()
    ticket = store.get(ticket_id)
    if ticket is None:
        raise ValueError(f"Ticket {ticket_id} not found")
    if not _can_read(user, ticket):
        raise PermissionError("access denied")
    return ticket


@mcp.tool()
def get_attachment(ticket_id: str, filename: str) -> str:
    """Return the text content of an attachment."""
    user = get_current_user()
    ticket = store.get(ticket_id)
    if ticket is None:
        raise ValueError(f"Ticket {ticket_id} not found")
    if not _can_read(user, ticket):
        raise PermissionError("access denied")
    try:
        return store.read_attachment(ticket_id, filename)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"attachment not found: {DATA_DIR}/attachments/{ticket_id}/{filename}"
        )


@mcp.tool()
def add_comment(ticket_id: str, body: str) -> dict:
    """Append a comment to a ticket."""
    user = get_current_user()
    ticket = store.get(ticket_id)
    if ticket is None:
        raise ValueError(f"Ticket {ticket_id} not found")
    if not _can_write(user, ticket):
        raise PermissionError("access denied")
    return store.add_comment(ticket_id, user["username"], body)


@mcp.tool()
def close_ticket(ticket_id: str, reason: str) -> dict:
    """Close a ticket."""
    user = get_current_user()
    ticket = store.get(ticket_id)
    if ticket is None:
        raise ValueError(f"Ticket {ticket_id} not found")
    if not _can_write(user, ticket):
        raise PermissionError("access denied")
    return store.close(ticket_id, reason)


@mcp.resource("ticket://{ticket_id}")
def read_ticket_resource(ticket_id: str) -> str:
    """Expose a ticket as an MCP resource."""
    ticket = store.get(ticket_id)
    if ticket is None:
        raise ValueError(f"Ticket {ticket_id} not found")
    return json.dumps(ticket, ensure_ascii=False, indent=2)


@mcp.prompt()
def summarize_ticket(ticket_id: str) -> str:
    """Build a summary prompt for the given ticket."""
    ticket = store.get(ticket_id)
    if ticket is None:
        raise ValueError(f"Ticket {ticket_id} not found")

    parts = [
        f"Summarize ticket {ticket['id']} - {ticket['subject']}.",
        f"Owner: {ticket.get('owner')}. Status: {ticket.get('status')}.",
        "",
        "Comments:",
    ]
    for c in ticket.get("comments", []):
        parts.append(f"- {c.get('author')}: {c.get('body')}")

    for name in ticket.get("attachments", []):
        try:
            content = store.read_attachment(ticket_id, name)
            parts.append(f"\n--- attachment: {name} ---\n{content}")
        except Exception as e:
            logger.warning("failed to read attachment %s: %s", name, e)

    return "\n".join(parts)


# --- HTTP transport ---

app = FastAPI()


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth.removeprefix("Bearer ").strip()
        try:
            user = verify_token(token)
            _current_user.set(user)
        except Exception:
            logger.exception("token verification failed, token=%s", token)
    return await call_next(request)


app.mount("/mcp", mcp.streamable_http_app())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
