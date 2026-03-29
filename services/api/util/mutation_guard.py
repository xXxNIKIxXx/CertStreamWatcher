from services.api.config import API_MUTATION_ENABLED
from fastapi import HTTPException
from fastapi.routing import APIRoute
import functools


def mutation_guard(func):
    """
    Decorator to block mutation routes if API_MUTATION_ENABLED is False.
    Also updates the OpenAPI schema to show a 403 response and a warning in the docs.
    """
    warning = "\n\n**DISABLED:** This endpoint is disabled because API_MUTATION_ENABLED is set to false. Change in env to enable."

    # Patch the OpenAPI schema for the route
    if hasattr(func, "__fastapi_route__"):
        route: APIRoute = func.__fastapi_route__
        if not API_MUTATION_ENABLED:
            # Add 403 response to OpenAPI
            # route.responses = route.responses or {}
            # route.responses[403] = {
            #     "description": "Mutations are disabled by config. Set API_MUTATION_ENABLED=true to enable."
            # }
            # Append warning to description
            if route.description:
                route.description += warning
            else:
                route.description = warning.strip()

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not API_MUTATION_ENABLED:
            raise HTTPException(
                status_code=403,
                detail="Mutations are disabled by config."
                "Set API_MUTATION_ENABLED=true to enable."
            )
        return func(*args, **kwargs)
    # Patch __doc__ for docs display
    if not API_MUTATION_ENABLED:
        if wrapper.__doc__:
            wrapper.__doc__ += warning
        else:
            wrapper.__doc__ = warning.strip()
    return wrapper
