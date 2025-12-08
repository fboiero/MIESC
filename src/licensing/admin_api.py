"""
API REST Admin para gestión de licencias MIESC.
Usa FastAPI para endpoints de administración.
"""

import os
from datetime import datetime, timedelta
from typing import Optional, List
from functools import wraps

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from .license_manager import LicenseManager
from .quota_checker import QuotaChecker
from .models import LicenseStatus, PlanType

# =============================================================================
# API Configuration
# =============================================================================

app = FastAPI(
    title="MIESC License Admin API",
    description="API REST para administración de licencias MIESC",
    version="1.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Admin API Key (should be set via environment variable)
ADMIN_API_KEY = os.getenv("MIESC_ADMIN_API_KEY", "miesc-admin-secret-key")

# Singleton instances
_license_manager: Optional[LicenseManager] = None
_quota_checker: Optional[QuotaChecker] = None


def get_license_manager() -> LicenseManager:
    """Get or create LicenseManager instance."""
    global _license_manager
    if _license_manager is None:
        _license_manager = LicenseManager()
    return _license_manager


def get_quota_checker() -> QuotaChecker:
    """Get or create QuotaChecker instance."""
    global _quota_checker
    if _quota_checker is None:
        _quota_checker = QuotaChecker()
    return _quota_checker


# =============================================================================
# Authentication
# =============================================================================

async def verify_admin_key(x_api_key: str = Header(..., alias="X-API-Key")):
    """Verify admin API key."""
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


# =============================================================================
# Pydantic Models
# =============================================================================

class LicenseCreateRequest(BaseModel):
    """Request to create a new license."""
    email: EmailStr
    plan: str = "FREE"
    organization: Optional[str] = None
    expires_days: Optional[int] = None
    notes: Optional[str] = None


class LicenseUpdateRequest(BaseModel):
    """Request to update a license."""
    plan: Optional[str] = None
    extend_days: Optional[int] = None
    notes: Optional[str] = None


class LicenseResponse(BaseModel):
    """License response model."""
    id: str
    license_key: str
    email: str
    organization: Optional[str]
    plan: str
    status: str
    created_at: str
    expires_at: Optional[str]
    is_active: bool
    max_audits_month: int
    allowed_tools: List[str]
    ai_enabled: bool


class UsageResponse(BaseModel):
    """Usage statistics response."""
    month: str
    audits_used: int
    audits_limit: str
    audits_remaining: str
    last_audit_at: Optional[str]
    plan: str
    allowed_tools: List[str]
    ai_enabled: bool
    max_contract_size_kb: int


class StatsResponse(BaseModel):
    """License statistics response."""
    total: int
    active: int
    expired: int
    suspended: int
    revoked: int
    by_plan: dict


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str
    success: bool


# =============================================================================
# API Endpoints
# =============================================================================

@app.get("/")
async def root():
    """API health check."""
    return {"status": "ok", "service": "MIESC License Admin API", "version": "1.0.0"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# License Management Endpoints
# -----------------------------------------------------------------------------

@app.post("/licenses", response_model=LicenseResponse, dependencies=[Depends(verify_admin_key)])
async def create_license(request: LicenseCreateRequest):
    """Create a new license."""
    manager = get_license_manager()

    try:
        plan_type = PlanType[request.plan.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {request.plan}")

    license_obj = manager.create_license(
        email=request.email,
        plan=plan_type,
        organization=request.organization,
        expires_days=request.expires_days,
        notes=request.notes,
    )

    return LicenseResponse(
        id=license_obj.id,
        license_key=license_obj.license_key,
        email=license_obj.email,
        organization=license_obj.organization,
        plan=license_obj.plan.value,
        status=license_obj.status.value,
        created_at=license_obj.created_at.isoformat(),
        expires_at=license_obj.expires_at.isoformat() if license_obj.expires_at else None,
        is_active=license_obj.is_active,
        max_audits_month=license_obj.max_audits_month,
        allowed_tools=license_obj.allowed_tools,
        ai_enabled=license_obj.ai_enabled,
    )


@app.get("/licenses", response_model=List[LicenseResponse], dependencies=[Depends(verify_admin_key)])
async def list_licenses(
    status: Optional[str] = Query(None, description="Filter by status (active, expired, suspended, revoked)"),
    plan: Optional[str] = Query(None, description="Filter by plan (FREE, STARTER, PRO, ENTERPRISE)"),
    email: Optional[str] = Query(None, description="Filter by email (partial match)"),
):
    """List all licenses with optional filters."""
    manager = get_license_manager()

    status_filter = None
    if status:
        try:
            status_filter = LicenseStatus[status.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    plan_filter = None
    if plan:
        try:
            plan_filter = PlanType[plan.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid plan: {plan}")

    licenses = manager.list_licenses(
        status=status_filter,
        plan=plan_filter,
        email=email,
    )

    return [
        LicenseResponse(
            id=lic.id,
            license_key=lic.license_key,
            email=lic.email,
            organization=lic.organization,
            plan=lic.plan.value,
            status=lic.status.value,
            created_at=lic.created_at.isoformat(),
            expires_at=lic.expires_at.isoformat() if lic.expires_at else None,
            is_active=lic.is_active,
            max_audits_month=lic.max_audits_month,
            allowed_tools=lic.allowed_tools,
            ai_enabled=lic.ai_enabled,
        )
        for lic in licenses
    ]


@app.get("/licenses/{license_key}", response_model=LicenseResponse, dependencies=[Depends(verify_admin_key)])
async def get_license(license_key: str):
    """Get a specific license by key."""
    manager = get_license_manager()
    license_obj = manager.get_license(license_key)

    if not license_obj:
        raise HTTPException(status_code=404, detail="License not found")

    return LicenseResponse(
        id=license_obj.id,
        license_key=license_obj.license_key,
        email=license_obj.email,
        organization=license_obj.organization,
        plan=license_obj.plan.value,
        status=license_obj.status.value,
        created_at=license_obj.created_at.isoformat(),
        expires_at=license_obj.expires_at.isoformat() if license_obj.expires_at else None,
        is_active=license_obj.is_active,
        max_audits_month=license_obj.max_audits_month,
        allowed_tools=license_obj.allowed_tools,
        ai_enabled=license_obj.ai_enabled,
    )


@app.put("/licenses/{license_key}", response_model=LicenseResponse, dependencies=[Depends(verify_admin_key)])
async def update_license(license_key: str, request: LicenseUpdateRequest):
    """Update an existing license."""
    manager = get_license_manager()

    # Get current license
    license_obj = manager.get_license(license_key)
    if not license_obj:
        raise HTTPException(status_code=404, detail="License not found")

    # Parse plan if provided
    new_plan = None
    if request.plan:
        try:
            new_plan = PlanType[request.plan.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid plan: {request.plan}")

    # Calculate new expiration if extending
    new_expires = None
    if request.extend_days:
        base = license_obj.expires_at or datetime.utcnow()
        new_expires = base + timedelta(days=request.extend_days)

    updated = manager.update_license(
        license_key,
        plan=new_plan,
        expires_at=new_expires,
        notes=request.notes,
    )

    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update license")

    return LicenseResponse(
        id=updated.id,
        license_key=updated.license_key,
        email=updated.email,
        organization=updated.organization,
        plan=updated.plan.value,
        status=updated.status.value,
        created_at=updated.created_at.isoformat(),
        expires_at=updated.expires_at.isoformat() if updated.expires_at else None,
        is_active=updated.is_active,
        max_audits_month=updated.max_audits_month,
        allowed_tools=updated.allowed_tools,
        ai_enabled=updated.ai_enabled,
    )


@app.post("/licenses/{license_key}/revoke", response_model=MessageResponse, dependencies=[Depends(verify_admin_key)])
async def revoke_license(license_key: str):
    """Revoke a license."""
    manager = get_license_manager()

    if manager.revoke_license(license_key):
        return MessageResponse(message=f"License {license_key} revoked", success=True)
    else:
        raise HTTPException(status_code=404, detail="License not found or already revoked")


@app.post("/licenses/{license_key}/suspend", response_model=MessageResponse, dependencies=[Depends(verify_admin_key)])
async def suspend_license(license_key: str):
    """Suspend a license."""
    manager = get_license_manager()

    if manager.suspend_license(license_key):
        return MessageResponse(message=f"License {license_key} suspended", success=True)
    else:
        raise HTTPException(status_code=404, detail="License not found or cannot be suspended")


@app.post("/licenses/{license_key}/reactivate", response_model=MessageResponse, dependencies=[Depends(verify_admin_key)])
async def reactivate_license(license_key: str):
    """Reactivate a suspended license."""
    manager = get_license_manager()

    if manager.reactivate_license(license_key):
        return MessageResponse(message=f"License {license_key} reactivated", success=True)
    else:
        raise HTTPException(status_code=404, detail="License not found or cannot be reactivated")


# Usage Endpoints
# -----------------------------------------------------------------------------

@app.get("/licenses/{license_key}/usage", response_model=UsageResponse, dependencies=[Depends(verify_admin_key)])
async def get_usage(license_key: str):
    """Get usage statistics for a license."""
    manager = get_license_manager()
    quota = get_quota_checker()

    license_obj = manager.get_license(license_key)
    if not license_obj:
        raise HTTPException(status_code=404, detail="License not found")

    usage = quota.get_usage(license_obj)

    return UsageResponse(
        month=usage["month"],
        audits_used=usage["audits_used"],
        audits_limit=str(usage["audits_limit"]),
        audits_remaining=str(usage["audits_remaining"]),
        last_audit_at=usage["last_audit_at"],
        plan=usage["plan"],
        allowed_tools=usage["allowed_tools"],
        ai_enabled=usage["ai_enabled"],
        max_contract_size_kb=usage["max_contract_size_kb"],
    )


# Statistics Endpoints
# -----------------------------------------------------------------------------

@app.get("/stats", response_model=StatsResponse, dependencies=[Depends(verify_admin_key)])
async def get_stats():
    """Get license statistics."""
    manager = get_license_manager()
    stats = manager.get_stats()

    return StatsResponse(
        total=stats["total"],
        active=stats["active"],
        expired=stats["expired"],
        suspended=stats["suspended"],
        revoked=stats["revoked"],
        by_plan=stats["by_plan"],
    )


# Public Validation Endpoint (no auth required)
# -----------------------------------------------------------------------------

@app.get("/validate/{license_key}")
async def validate_license(license_key: str):
    """
    Public endpoint to validate a license key.
    Returns minimal info without requiring admin authentication.
    """
    manager = get_license_manager()
    license_obj = manager.validate(license_key)

    if license_obj:
        return {
            "valid": True,
            "plan": license_obj.plan.value,
            "days_remaining": license_obj.days_until_expiry,
        }
    else:
        return {
            "valid": False,
            "plan": None,
            "days_remaining": None,
        }


# =============================================================================
# Run Server
# =============================================================================

def run_server(host: str = "0.0.0.0", port: int = 5002):
    """Run the admin API server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
