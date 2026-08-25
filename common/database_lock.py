from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from typing import BinaryIO, Iterator


_state = threading.local()


def _state_map() -> dict[str, dict[str, object]]:
    value = getattr(_state, "database_locks", None)
    if value is None:
        value = {}
        _state.database_locks = value
    return value


def _acquire(handle: BinaryIO, *, exclusive: bool, blocking: bool) -> None:
    if os.name == "nt":
        import msvcrt

        # msvcrt has no shared advisory-lock primitive. Serializing all database
        # users on Windows keeps local tests safe; production Linux uses shared
        # locks for normal traffic and an exclusive lock only for restore.
        handle.seek(0)
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"\0")
            handle.flush()
        mode = msvcrt.LK_NBLCK
        while True:
            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), mode, 1)
                return
            except OSError:
                if not blocking:
                    raise
                time.sleep(0.05)

    import fcntl

    flags = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    if not blocking:
        flags |= fcntl.LOCK_NB
    fcntl.flock(handle.fileno(), flags)


def _release(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def database_access(
    database_path: str,
    *,
    exclusive: bool = False,
    blocking: bool = True,
) -> Iterator[None]:
    """Coordinate live SQLite access across API, worker, backup and restore.

    The lock lives beside the database on the shared data volume. Calls are
    re-entrant in one thread so restore may run migrations and health queries
    while retaining the exclusive cross-process barrier.
    """

    absolute_database_path = os.path.abspath(database_path)
    lock_path = os.environ.get("LOKI_WATCHER_DB_LOCK", f"{absolute_database_path}.lock")
    states = _state_map()
    current = states.get(lock_path)
    if current is not None:
        if exclusive and current["mode"] != "exclusive":
            raise RuntimeError("cannot upgrade a shared database lock")
        current["depth"] = int(current["depth"]) + 1
        try:
            yield
        finally:
            current["depth"] = int(current["depth"]) - 1
        return

    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
    handle = open(lock_path, "a+b")
    try:
        _acquire(handle, exclusive=exclusive, blocking=blocking)
        states[lock_path] = {
            "depth": 1,
            "handle": handle,
            "mode": "exclusive" if exclusive else "shared",
        }
        try:
            yield
        finally:
            states.pop(lock_path, None)
            _release(handle)
    finally:
        handle.close()
