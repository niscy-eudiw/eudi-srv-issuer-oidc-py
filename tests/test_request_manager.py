"""Thread safety and bounds of the in-memory authorization request store."""

import datetime
import threading
import time

import pytest

from request_manager import RequestLimitExceeded, RequestManager


def _expire(manager, session_id):
    manager._requests[session_id].expiry_time = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(seconds=1)


def test_expired_lookup_releases_the_index_lock_before_removal(monkeypatch):
    """Holding an index lock while taking every lock (from _requests_lock)
    deadlocked against clean_expired_requests."""
    manager = RequestManager()
    manager.add_request("c", "https://w.test/cb", "code", session_id="s")
    manager.update_code("s", "the-code")
    _expire(manager, "s")

    held = {}
    original = manager._remove_request_from_all_managers

    def remove(request_obj):
        free = []

        def try_lock():
            acquired = manager._requests_by_code_lock.acquire(blocking=False)
            free.append(acquired)
            if acquired:
                manager._requests_by_code_lock.release()

        probe = threading.Thread(target=try_lock)
        probe.start()
        probe.join()
        held["index_lock_free"] = free[0]
        return original(request_obj)

    monkeypatch.setattr(manager, "_remove_request_from_all_managers", remove)
    assert manager.get_request_by_code("the-code") is None
    assert held["index_lock_free"] is True


def test_store_is_capped():
    manager = RequestManager(max_requests=3)
    for i in range(3):
        manager.add_request("c", "https://w.test/cb", "code", session_id=f"s{i}")
    with pytest.raises(RequestLimitExceeded):
        manager.add_request("c", "https://w.test/cb", "code", session_id="s3")


def test_expired_requests_make_room():
    manager = RequestManager(max_requests=2)
    manager.add_request("c", "https://w.test/cb", "code", session_id="old")
    manager.add_request("c", "https://w.test/cb", "code", session_id="new")
    _expire(manager, "old")
    manager.add_request("c", "https://w.test/cb", "code", session_id="newer")
    assert manager.get_request("old") is None
    assert manager.get_request("newer") is not None


def test_expired_requests_are_cleaned_without_an_authorization_request(monkeypatch):
    manager = RequestManager()
    manager.add_request("c", "https://w.test/cb", "code", session_id="old")
    _expire(manager, "old")
    # The last clean was one interval ago, whatever the host's uptime.
    manager._last_clean = time.monotonic() - manager.CLEAN_INTERVAL
    manager.add_request("c", "https://w.test/cb", "code", session_id="new")
    assert "old" not in manager._requests


def test_cleaning_does_not_depend_on_host_uptime(monkeypatch):
    """time.monotonic() counts from boot: a host up for less than CLEAN_INTERVAL never cleaned."""
    import request_manager

    monkeypatch.setattr(request_manager.time, "monotonic", lambda: 5.0)  # 5 s after boot
    manager = RequestManager()
    manager.add_request("c", "https://w.test/cb", "code", session_id="old")
    _expire(manager, "old")
    manager._last_clean = float("-inf")
    manager.add_request("c", "https://w.test/cb", "code", session_id="new")
    assert "old" not in manager._requests
