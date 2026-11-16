"""
Rate limiting via slowapi (a Flask-Limiter-style wrapper for FastAPI/Starlette).

Design decision: keyed by remote IP, applied per-route rather than
globally, because different endpoints have wildly different acceptable
request rates — a login endpoint needs tight limits (defends against
credential-stuffing/brute-force), a read-only dashboard endpoint doesn't.

`enabled=False` in the test environment is deliberate, not a workaround
to "make tests pass": slowapi's in-memory limiter persists for the whole
pytest process, so a handful of tests each calling /auth/register would
otherwise trip the real 5/minute production limit and fail for a reason
that has nothing to do with the code under test. Tests should fail when
the APPLICATION is wrong, not when the TEST SUITE'S calling pattern
coincidentally resembles an attack — that's a meaningfully different
signal and conflating them makes real failures harder to trust.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings

settings = get_settings()

limiter = Limiter(key_func=get_remote_address, enabled=(settings.APP_ENV != "test"))
