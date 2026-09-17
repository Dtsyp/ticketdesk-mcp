# TicketDesk MCP

MCP server for our internal ticket system. Supports stdio (Claude Desktop,
IDE plugins) and streamable HTTP (our orchestrator).

## Run locally (stdio)

    pip install -r requirements.txt
    # stdio is the default transport; identity comes from the local env
    TICKETDESK_USER=alice TICKETDESK_GROUPS=eng python server.py

`python server.py` starts stdio. Set `TICKETDESK_TRANSPORT=http` to run the
HTTP app instead (or use uvicorn, as the container does).

## Run via docker compose (http)

    cp .env.example .env      # fill in the secrets
    docker compose up -d
    curl -H "Authorization: Bearer <token>" http://localhost:8000/mcp

Over HTTP a **valid** bearer token is required; requests without one get 401.
`GET /healthz` and `/readyz` are unauthenticated for probes.

## Design decisions

- JWT is verified against Keycloak JWKS with RS256 only, and `exp`/`iss`/`aud`
  enforced (see `auth.py`). We do not trust the token just because Keycloak
  issued it - Keycloak is not in the request path.
- ACLs are applied everywhere a ticket leaves the server: `search_tickets`,
  `get_ticket`, `get_attachment`, the `ticket://` resource and the
  `summarize_ticket` prompt.
- Attachments are served as UTF-8 text; non-text files are refused rather than
  returned as mojibake.
- Attachment names are validated against the ticket's declared attachments and
  cannot traverse out of the data directory.
- Over HTTP the caller is set by a pure-ASGI auth layer; over stdio it comes
  from the environment. There is no env-var identity on the HTTP path.

## Tools

- `search_tickets(query, status?, assignee?, limit?)` - free-text substring search
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
- Shared store for multi-worker deployments (writes are process-local locked)

## Secrets

`TICKETDESK_JWKS_URL`, `TICKETDESK_ISSUER` and `TICKETDESK_AUDIENCE` are read
from the environment. See `.env.example`; the real `.env` is not committed.
