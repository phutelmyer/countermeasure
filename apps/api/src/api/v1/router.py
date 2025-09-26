"""
Main API router for v1 endpoints.
"""

from fastapi import APIRouter

from .endpoints import actors, auth, detections, mitre, tenants, users


# Create main API router
api_router = APIRouter()

# Include endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

api_router.include_router(actors.router, prefix="/actors", tags=["Actors"])

api_router.include_router(detections.router, prefix="/detections", tags=["Detections"])

api_router.include_router(mitre.router, prefix="/mitre", tags=["MITRE ATT&CK"])
# api_router.include_router(intelligence.router, prefix="/intelligence", tags=["Intelligence"])
api_router.include_router(tenants.router, prefix="/tenants", tags=["Tenants"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
