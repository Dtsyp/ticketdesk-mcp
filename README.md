# TicketDesk MCP

MCP server for our internal ticket system. Supports stdio (Claude Desktop,
IDE plugins) and streamable HTTP (our orchestrator).

## Run locally (stdio)

    pip install -r requirements.txt
    TICKETDESK_USER=alice TICKETDESK_GROUPS=eng python server.py

## Run via docker compose (http)

    docker compose up -d
    curl -H "Authorization: Bearer ***" http://localhost:8000/mcp

## Design decisions

- JWT verification goes through Keycloak JWKS (see `auth.py`).
- ACLs are applied on the read path (`get_ticket`, `get_attachment`).
- Attachments are returned as text for simplicity.
- User context is passed to tools via a contextvar set by FastAPI middleware.

## Tools

- `search_tickets(query, status?, assignee?)`
- `get_ticket(ticket_id)`
- `get_attachment(ticket_id, filename)`
- `add_comment(ticket_id, body)` - requires scope `tickets:write`
- `close_ticket(ticket_id, reason)` - requires scope `tickets:write`

Resource: `ticket://{id}`
Prompt: `summarize_ticket(ticket_id)`

## Not done yet

- Rate limiting
- Per-tool timeouts
- Metrics beyond basic logs

## Secrets

`TICKETDESK_JWKS_URL` and `TICKETDESK_ISSUER` are read from the environment.
Defaults are in `.env` for local development.
