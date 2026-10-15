"""
SentinelAI - Response Engine Compatibility Wrapper
Preserves backwards compatibility for the misspelled 'response_enigne' module.
Redirects all classes and helpers to the canonical 'response_engine' module.
"""

from response_engine import (
    ResponseEngine,
    get_response_engine,
    sanitize_ip,
)

__all__ = ["ResponseEngine", "get_response_engine", "sanitize_ip"]