"""Auth gate and per-request identity through the real streamable HTTP
transport, in-process (no network, no Keycloak)."""
import itertools
import json

import httpx
import pytest

import server

pytestmark = pytest.mark.anyio

MCP = "/mcp"
HEADERS = {"Accept": "application/json, text/event-stream",
           "Content-Type": "application/json"}
INIT = {"protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "tests", "version": "0"}}
_ids = itertools.count(1)


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
async def _session_manager():
    # what the app lifespan does under uvicorn; run() is once-per-instance in
    # the SDK, hence module scope
    async with server.mcp.session_manager.run():
        yield


@pytest.fixture
async def client(_session_manager, store, monkeypatch):
    monkeypatch.setattr(server, "store", store)
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _rpc(method, params=None):
    msg = {"jsonrpc": "2.0", "id": next(_ids), "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _result(r):
    # POST responses come back as a one-message SSE stream
    for line in r.text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:])["result"]
    return r.json()["result"]


def _hdr(token, session=None):
    h = dict(HEADERS, Authorization=f"Bearer {token}")
    if session:
        h["mcp-session-id"] = session
    return h


async def _init(client, token):
    r = await client.post(MCP, json=_rpc("initialize", INIT), headers=_hdr(token))
    assert r.status_code == 200, r.text
    sid = r.headers["mcp-session-id"]
    r = await client.post(MCP, json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                          headers=_hdr(token, sid))
    assert r.status_code == 202, r.text
    return sid


async def _call(client, token, sid, name, **arguments):
    r = await client.post(MCP, json=_rpc("tools/call", {"name": name, "arguments": arguments}),
                          headers=_hdr(token, sid))
    assert r.status_code == 200, r.text
    res = _result(r)
    # FastMCP turns a list result into one content item per element
    return res.get("isError", False), [c["text"] for c in res["content"]]


async def test_health_public(client):
    assert (await client.get("/healthz")).status_code == 200
    assert (await client.get("/readyz")).status_code == 200


async def test_401_without_valid_token(client):
    r = await client.post(MCP, json=_rpc("initialize", INIT), headers=HEADERS)
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")
    r = await client.post(MCP, json=_rpc("initialize", INIT), headers=_hdr("not-a-jwt"))
    assert r.status_code == 401


async def test_mcp_path_and_lifespan(client, mint):
    # /mcp (not /mcp/mcp) and the session manager is actually running
    assert await _init(client, mint())


async def test_identity_per_request(client, mint, store):
    (store.tickets_dir / "T-2.json").write_text(json.dumps({
        "id": "T-2", "subject": "hr only", "owner": "carol", "groups": ["hr"],
        "status": "open", "comments": [], "attachments": [],
    }), encoding="utf-8")
    alice = mint(preferred_username="alice", groups=["/eng"])
    carol = mint(preferred_username="carol", groups=["/hr"])

    sid = await _init(client, alice)
    err, out = await _call(client, alice, sid, "get_ticket", ticket_id="T-1")
    assert not err and json.loads(out[0])["owner"] == "alice"

    # carol's token on the session alice opened must act as carol
    err, out = await _call(client, carol, sid, "get_ticket", ticket_id="T-1")
    assert err and "not found" in out[0]
    err, out = await _call(client, carol, sid, "get_ticket", ticket_id="T-2")
    assert not err and json.loads(out[0])["owner"] == "carol"
    err, out = await _call(client, carol, sid, "search_tickets", query="")
    assert not err and [json.loads(t)["id"] for t in out] == ["T-2"]


async def test_session_id_is_not_auth(client, mint):
    sid = await _init(client, mint())
    r = await client.post(MCP, json=_rpc("tools/call", {"name": "get_ticket",
                                                          "arguments": {"ticket_id": "T-1"}}),
                          headers=dict(HEADERS, **{"mcp-session-id": sid}))
    assert r.status_code == 401
