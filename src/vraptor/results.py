"""Execution boundary for existing-evidence analysis."""
from contextlib import contextmanager
from contextvars import ContextVar

_existing_only = ContextVar("vraptor_existing_only", default=False)


@contextmanager
def operation_policy(*, existing_only=False):
    token = _existing_only.set(existing_only or _existing_only.get())
    try:
        yield
    finally:
        _existing_only.reset(token)


def require_remote_mutation(operation):
    if _existing_only.get():
        raise RuntimeError(f"Existing-evidence analysis forbids remote mutation: {operation}")
