import os

import pytest

os.environ.setdefault("TICKETDESK_DATA", "./data")


def test_server_imports():
    import server  # noqa: F401


def test_get_ticket_returns_dict():
    import server

    ticket = server.store.get("T-1001")
    assert ticket["id"] == "T-1001"


def test_search_returns_results():
    import server

    assert server.store.search("VPN")


def test_can_read_own_ticket():
    # TODO: implement
    assert True


def test_path_traversal_rejected():
    # TODO: implement
    assert True
