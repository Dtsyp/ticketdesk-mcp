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

The `seed` one-shot copies `data/` into the volume on first start and hands it
to the app uid; the image itself carries no data.

Over HTTP a **valid** bearer token is required; requests without one get 401.
`GET /healthz` and `/readyz` are unauthenticated for probes. The MCP endpoint
is `/mcp` (trailing slash optional).

## Design decisions

- JWT is verified against Keycloak JWKS with RS256 only, and `exp`/`iss`/`aud`
  enforced (see `auth.py`). We do not trust the token just because Keycloak
  issued it - Keycloak is not in the request path.
- `aud` must be `ticketdesk-mcp`, i.e. this service, not the calling client.
  The realm export carries the audience and group-membership mappers the
  server relies on; without them tokens have no `groups` and a wrong `aud`.
- Over HTTP the caller is set per request: the ASGI auth layer verifies the
  token and puts the principal into the request state, tools read it from the
  current request. Not from a contextvar - in stateful streamable HTTP the
  session task keeps the context of the `initialize` request, which would pin
  the whole session to the first caller.
- Over stdio identity comes from the environment (read-only by default). There
  is no env-var identity on the HTTP path.
- ACLs are applied everywhere a ticket leaves the server: `search_tickets`
  (inside the scan, before `limit`), `get_ticket`, `get_attachment`, the
  `ticket://` resource and the `summarize_ticket` prompt. A ticket you cannot
  read looks like a ticket that does not exist.
- Attachments are served as UTF-8 text and capped by
  `TICKETDESK_MAX_ATTACHMENT_BYTES` (1 MiB by default). Binaries and oversized
  files are refused with a clear error; names are validated against the
  ticket's declared attachments and cannot traverse out of the data directory.
- The MCP app is served directly (`server:app`), not mounted into another
  framework: Starlette does not run lifespans of mounted apps, and the
  streamable HTTP session manager lives in the lifespan.

## Tools

- `search_tickets(query, status?, assignee?, limit?)` - free-text substring search
- `get_ticket(ticket_id)`
- `get_attachment(ticket_id, filename)`
- `add_comment(ticket_id, body)` - requires scope `tickets:write`
- `close_ticket(ticket_id, reason)` - requires scope `tickets:write`

Resource: `ticket://{id}`
Prompt: `summarize_ticket(ticket_id)`

## Tests

    pip install -r requirements-dev.txt
    pytest -q

`tests/test_http.py` drives the real streamable HTTP transport in-process
(401s, session handling, per-request identity) with locally minted RS256
tokens - no Keycloak needed.

## Not done yet

- Rate limiting
- Per-tool timeouts
- Metrics beyond basic logs
- Shared store for multi-worker deployments (writes are process-local locked)

## Secrets

`TICKETDESK_JWKS_URL`, `TICKETDESK_ISSUER` and `TICKETDESK_AUDIENCE` are read
from the environment. See `.env.example`; the real `.env` is not committed.
