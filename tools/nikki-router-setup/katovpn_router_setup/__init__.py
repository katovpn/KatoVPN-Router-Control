"""KatoVPN local Nikki router setup wizard."""

from .core import (
    PROFILE_NAME,
    USER_AGENT,
    SetupError,
    configure_router,
    preflight_router,
    validate_inputs,
    validate_portable_template,
    validate_subscription_document,
)

__all__ = [
    "PROFILE_NAME",
    "USER_AGENT",
    "SetupError",
    "configure_router",
    "preflight_router",
    "validate_inputs",
    "validate_portable_template",
    "validate_subscription_document",
]
