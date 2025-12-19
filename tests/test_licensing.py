"""
Comprehensive tests for the MIESC licensing module.
Tests models, plans, key_generator, license_manager, and quota_checker.
"""

import pytest
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os

# Import licensing modules
from src.licensing.models import (
    LicenseStatus, PlanType, LicenseDB, UsageRecordDB,
    License, UsageRecord, Base
)
from src.licensing.plans import (
    PLANS, ALL_TOOLS, TOOLS_LAYER_1, TOOLS_LAYER_2, TOOLS_LAYER_3,
    get_plan_config, get_allowed_tools, is_tool_allowed,
    get_max_audits, get_max_contract_size, is_ai_enabled
)
from src.licensing.key_generator import (
    generate_license_key, validate_key_format, normalize_key,
    generate_checksum, generate_key_with_checksum
)
from src.licensing.license_manager import LicenseManager
from src.licensing.quota_checker import QuotaChecker


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def temp_db_url():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    url = f"sqlite:///{db_path}"
    yield url
    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
def license_manager(temp_db_url):
    """Create a LicenseManager with a temporary database."""
    return LicenseManager(database_url=temp_db_url)


@pytest.fixture
def quota_checker(temp_db_url):
    """Create a QuotaChecker with a temporary database."""
    return QuotaChecker(database_url=temp_db_url)


@pytest.fixture
def sample_license():
    """Create a sample License object."""
    return License(
        id=str(uuid.uuid4()),
        license_key="MIESC-ABCD-1234-EFGH-5678",
        email="test@example.com",
        plan=PlanType.PRO,
        status=LicenseStatus.ACTIVE,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=365),
        organization="Test Org",
        max_audits_month=500,
        allowed_tools=ALL_TOOLS,
        ai_enabled=True,
        max_contract_size_kb=1024
    )


@pytest.fixture
def expired_license():
    """Create an expired license."""
    return License(
        id=str(uuid.uuid4()),
        license_key="MIESC-DEAD-BEEF-CAFE-BABE",
        email="expired@example.com",
        plan=PlanType.FREE,
        status=LicenseStatus.ACTIVE,  # Status is active but date is expired
        created_at=datetime.utcnow() - timedelta(days=400),
        expires_at=datetime.utcnow() - timedelta(days=30),  # Expired 30 days ago
        max_audits_month=5,
        allowed_tools=["slither", "solhint"],
        ai_enabled=False,
        max_contract_size_kb=50
    )


@pytest.fixture
def suspended_license():
    """Create a suspended license."""
    return License(
        id=str(uuid.uuid4()),
        license_key="MIESC-SUSP-ENDE-DLIC-ENSE",
        email="suspended@example.com",
        plan=PlanType.STARTER,
        status=LicenseStatus.SUSPENDED,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=365),
        max_audits_month=50,
        allowed_tools=["slither", "solhint", "aderyn", "mythril", "echidna"],
        ai_enabled=False,
        max_contract_size_kb=200
    )


@pytest.fixture
def enterprise_license():
    """Create an enterprise license (unlimited)."""
    return License(
        id=str(uuid.uuid4()),
        license_key="MIESC-ENTE-RPRI-SELI-CENS",
        email="enterprise@example.com",
        plan=PlanType.ENTERPRISE,
        status=LicenseStatus.ACTIVE,
        created_at=datetime.utcnow(),
        expires_at=None,  # Perpetual
        max_audits_month=-1,  # Unlimited
        allowed_tools=ALL_TOOLS,
        ai_enabled=True,
        max_contract_size_kb=-1  # Unlimited
    )


# =============================================================================
# Tests for models.py - Enums
# =============================================================================

class TestLicenseStatus:
    """Tests for LicenseStatus enum."""

    def test_license_status_values(self):
        """Test all license status values exist."""
        assert LicenseStatus.ACTIVE == "active"
        assert LicenseStatus.EXPIRED == "expired"
        assert LicenseStatus.SUSPENDED == "suspended"
        assert LicenseStatus.REVOKED == "revoked"

    def test_license_status_is_string(self):
        """Test that status values are strings."""
        assert isinstance(LicenseStatus.ACTIVE.value, str)


class TestPlanType:
    """Tests for PlanType enum."""

    def test_plan_type_values(self):
        """Test all plan type values exist."""
        assert PlanType.FREE == "FREE"
        assert PlanType.STARTER == "STARTER"
        assert PlanType.PRO == "PRO"
        assert PlanType.ENTERPRISE == "ENTERPRISE"

    def test_plan_type_count(self):
        """Test that we have exactly 4 plan types."""
        assert len(PlanType) == 4


# =============================================================================
# Tests for models.py - License Dataclass
# =============================================================================

class TestLicenseDataclass:
    """Tests for License dataclass."""

    def test_license_creation(self, sample_license):
        """Test license creation with all fields."""
        assert sample_license.email == "test@example.com"
        assert sample_license.plan == PlanType.PRO
        assert sample_license.status == LicenseStatus.ACTIVE

    def test_is_active_with_active_license(self, sample_license):
        """Test is_active returns True for active, unexpired license."""
        assert sample_license.is_active is True

    def test_is_active_with_expired_license(self, expired_license):
        """Test is_active returns False for expired license."""
        assert expired_license.is_active is False

    def test_is_active_with_suspended_license(self, suspended_license):
        """Test is_active returns False for suspended license."""
        assert suspended_license.is_active is False

    def test_is_expired_with_valid_license(self, sample_license):
        """Test is_expired returns False for valid license."""
        assert sample_license.is_expired is False

    def test_is_expired_with_expired_license(self, expired_license):
        """Test is_expired returns True for expired license."""
        assert expired_license.is_expired is True

    def test_is_expired_with_perpetual_license(self, enterprise_license):
        """Test is_expired returns False for perpetual license."""
        assert enterprise_license.is_expired is False

    def test_days_until_expiry_with_future_date(self, sample_license):
        """Test days_until_expiry with future expiration."""
        days = sample_license.days_until_expiry
        assert days is not None
        assert days > 0

    def test_days_until_expiry_with_expired(self, expired_license):
        """Test days_until_expiry returns 0 for expired license."""
        days = expired_license.days_until_expiry
        assert days == 0

    def test_days_until_expiry_with_perpetual(self, enterprise_license):
        """Test days_until_expiry returns None for perpetual license."""
        assert enterprise_license.days_until_expiry is None

    def test_to_dict(self, sample_license):
        """Test to_dict method."""
        d = sample_license.to_dict()
        assert d["email"] == "test@example.com"
        assert d["plan"] == "PRO"
        assert d["status"] == "active"
        assert d["is_active"] is True
        assert "license_key" in d
        assert "created_at" in d

    def test_to_dict_with_none_expires(self, enterprise_license):
        """Test to_dict with None expires_at."""
        d = enterprise_license.to_dict()
        assert d["expires_at"] is None

    def test_from_db(self):
        """Test from_db class method."""
        # Create a mock DB object
        mock_db = Mock()
        mock_db.id = str(uuid.uuid4())
        mock_db.license_key = "MIESC-TEST-TEST-TEST-TEST"
        mock_db.email = "db@test.com"
        mock_db.organization = "Test"
        mock_db.plan = PlanType.STARTER
        mock_db.status = LicenseStatus.ACTIVE
        mock_db.created_at = datetime.utcnow()
        mock_db.expires_at = None
        mock_db.last_validated_at = None
        mock_db.notes = "Test note"

        plan_config = {
            "max_audits_month": 50,
            "allowed_tools": ["slither"],
            "ai_enabled": False,
            "max_contract_size_kb": 200
        }

        license = License.from_db(mock_db, plan_config)
        assert license.email == "db@test.com"
        assert license.max_audits_month == 50
        assert license.ai_enabled is False


# =============================================================================
# Tests for models.py - UsageRecord Dataclass
# =============================================================================

class TestUsageRecordDataclass:
    """Tests for UsageRecord dataclass."""

    def test_usage_record_creation(self):
        """Test UsageRecord creation."""
        record = UsageRecord(
            id=str(uuid.uuid4()),
            license_id=str(uuid.uuid4()),
            month="2024-12",
            audits_count=10,
            last_audit_at=datetime.utcnow()
        )
        assert record.audits_count == 10
        assert record.month == "2024-12"

    def test_usage_record_to_dict(self):
        """Test UsageRecord to_dict method."""
        now = datetime.utcnow()
        record = UsageRecord(
            id="test-id",
            license_id="license-id",
            month="2024-12",
            audits_count=5,
            last_audit_at=now
        )
        d = record.to_dict()
        assert d["id"] == "test-id"
        assert d["audits_count"] == 5
        assert d["last_audit_at"] is not None

    def test_usage_record_to_dict_without_last_audit(self):
        """Test UsageRecord to_dict with None last_audit_at."""
        record = UsageRecord(
            id="test-id",
            license_id="license-id",
            month="2024-12",
            audits_count=0,
            last_audit_at=None
        )
        d = record.to_dict()
        assert d["last_audit_at"] is None


# =============================================================================
# Tests for plans.py
# =============================================================================

class TestPlans:
    """Tests for plans module."""

    def test_plans_dict_has_all_types(self):
        """Test that PLANS contains all PlanTypes."""
        for plan_type in PlanType:
            assert plan_type in PLANS

    def test_all_tools_includes_layer_tools(self):
        """Test ALL_TOOLS contains tools from all layers."""
        for tool in TOOLS_LAYER_1:
            assert tool in ALL_TOOLS
        for tool in TOOLS_LAYER_2:
            assert tool in ALL_TOOLS
        for tool in TOOLS_LAYER_3:
            assert tool in ALL_TOOLS

    def test_get_plan_config_free(self):
        """Test get_plan_config for FREE plan."""
        config = get_plan_config(PlanType.FREE)
        assert config["max_audits_month"] == 5
        assert config["ai_enabled"] is False
        assert "slither" in config["allowed_tools"]

    def test_get_plan_config_enterprise(self):
        """Test get_plan_config for ENTERPRISE plan."""
        config = get_plan_config(PlanType.ENTERPRISE)
        assert config["max_audits_month"] == -1  # Unlimited
        assert config["ai_enabled"] is True

    def test_get_plan_config_invalid(self):
        """Test get_plan_config with invalid type falls back to FREE."""
        # Using a string that doesn't exist should use default
        config = get_plan_config("INVALID")
        # Should return FREE plan config
        assert config == PLANS[PlanType.FREE]

    def test_get_allowed_tools_free(self):
        """Test get_allowed_tools for FREE plan."""
        tools = get_allowed_tools(PlanType.FREE)
        assert "slither" in tools
        assert "solhint" in tools
        assert len(tools) == 2

    def test_get_allowed_tools_pro(self):
        """Test get_allowed_tools for PRO plan."""
        tools = get_allowed_tools(PlanType.PRO)
        assert tools == ALL_TOOLS

    def test_is_tool_allowed_free_plan(self):
        """Test is_tool_allowed for FREE plan."""
        assert is_tool_allowed(PlanType.FREE, "slither") is True
        assert is_tool_allowed(PlanType.FREE, "mythril") is False

    def test_is_tool_allowed_case_insensitive(self):
        """Test is_tool_allowed is case insensitive."""
        assert is_tool_allowed(PlanType.FREE, "SLITHER") is True
        assert is_tool_allowed(PlanType.FREE, "Slither") is True

    def test_is_tool_allowed_pro_plan(self):
        """Test is_tool_allowed for PRO plan."""
        assert is_tool_allowed(PlanType.PRO, "mythril") is True
        assert is_tool_allowed(PlanType.PRO, "certora") is True

    def test_get_max_audits_free(self):
        """Test get_max_audits for FREE plan."""
        assert get_max_audits(PlanType.FREE) == 5

    def test_get_max_audits_enterprise(self):
        """Test get_max_audits for ENTERPRISE plan."""
        assert get_max_audits(PlanType.ENTERPRISE) == -1

    def test_get_max_contract_size_free(self):
        """Test get_max_contract_size for FREE plan."""
        assert get_max_contract_size(PlanType.FREE) == 50

    def test_get_max_contract_size_enterprise(self):
        """Test get_max_contract_size for ENTERPRISE plan."""
        assert get_max_contract_size(PlanType.ENTERPRISE) == -1

    def test_is_ai_enabled_free(self):
        """Test is_ai_enabled for FREE plan."""
        assert is_ai_enabled(PlanType.FREE) is False

    def test_is_ai_enabled_pro(self):
        """Test is_ai_enabled for PRO plan."""
        assert is_ai_enabled(PlanType.PRO) is True


# =============================================================================
# Tests for key_generator.py
# =============================================================================

class TestKeyGenerator:
    """Tests for key generator functions."""

    def test_generate_license_key_format(self):
        """Test that generated keys have correct format."""
        key = generate_license_key()
        assert key.startswith("MIESC-")
        parts = key.split("-")
        assert len(parts) == 5
        assert parts[0] == "MIESC"
        for part in parts[1:]:
            assert len(part) == 4
            assert part.isalnum()

    def test_generate_license_key_unique(self):
        """Test that generated keys are unique."""
        keys = [generate_license_key() for _ in range(100)]
        assert len(keys) == len(set(keys))

    def test_validate_key_format_valid(self):
        """Test validate_key_format with valid key."""
        # Note: hex characters are 0-9 and A-F only (G-Z are invalid)
        assert validate_key_format("MIESC-ABCD-1234-EFAB-5678") is True
        assert validate_key_format("MIESC-0000-0000-0000-0000") is True

    def test_validate_key_format_invalid(self):
        """Test validate_key_format with invalid keys."""
        assert validate_key_format("INVALID") is False
        assert validate_key_format("MIESC-ABC-1234-EFAB-5678") is False  # Too short
        assert validate_key_format("MIESC-ABCDE-1234-EFAB-5678") is False  # Too long
        assert validate_key_format("OTHER-ABCD-1234-EFAB-5678") is False  # Wrong prefix
        assert validate_key_format("MIESC-GHIJ-1234-EFAB-5678") is False  # Invalid hex (G-J not valid)

    def test_validate_key_format_case_insensitive(self):
        """Test validate_key_format is case insensitive."""
        assert validate_key_format("miesc-abcd-1234-efab-5678") is True

    def test_normalize_key_valid(self):
        """Test normalize_key with valid key."""
        key = normalize_key("miesc-abcd-1234-efab-5678")
        assert key == "MIESC-ABCD-1234-EFAB-5678"

    def test_normalize_key_with_spaces(self):
        """Test normalize_key removes spaces."""
        key = normalize_key("  MIESC-ABCD-1234-EFAB-5678  ")
        assert key == "MIESC-ABCD-1234-EFAB-5678"

    def test_normalize_key_without_prefix(self):
        """Test normalize_key adds prefix if needed."""
        key = normalize_key("ABCD1234EFAB5678")
        assert key == "MIESC-ABCD-1234-EFAB-5678"

    def test_normalize_key_empty(self):
        """Test normalize_key with empty string."""
        assert normalize_key("") is None
        assert normalize_key(None) is None

    def test_normalize_key_invalid(self):
        """Test normalize_key with invalid key."""
        assert normalize_key("invalid-key") is None

    def test_generate_checksum(self):
        """Test generate_checksum."""
        key = "MIESC-ABCD-1234-EFAB-5678"
        checksum = generate_checksum(key)
        assert len(checksum) == 8
        assert checksum.isalnum()
        assert checksum.isupper()

    def test_generate_checksum_deterministic(self):
        """Test generate_checksum is deterministic."""
        key = "MIESC-ABCD-1234-EFAB-5678"
        cs1 = generate_checksum(key)
        cs2 = generate_checksum(key)
        assert cs1 == cs2

    def test_generate_key_with_checksum(self):
        """Test generate_key_with_checksum."""
        key, checksum = generate_key_with_checksum()
        assert validate_key_format(key) is True
        assert len(checksum) == 8
        assert generate_checksum(key) == checksum


# =============================================================================
# Tests for license_manager.py
# =============================================================================

class TestLicenseManager:
    """Tests for LicenseManager class."""

    def test_create_license_basic(self, license_manager):
        """Test basic license creation."""
        license = license_manager.create_license(
            email="test@example.com",
            plan=PlanType.FREE
        )
        assert license is not None
        assert license.email == "test@example.com"
        assert license.plan == PlanType.FREE
        assert license.status == LicenseStatus.ACTIVE
        assert validate_key_format(license.license_key) is True

    def test_create_license_with_organization(self, license_manager):
        """Test license creation with organization."""
        license = license_manager.create_license(
            email="corp@example.com",
            plan=PlanType.ENTERPRISE,
            organization="Test Corp"
        )
        assert license.organization == "Test Corp"

    def test_create_license_with_expiration(self, license_manager):
        """Test license creation with expiration."""
        license = license_manager.create_license(
            email="trial@example.com",
            plan=PlanType.STARTER,
            expires_days=30
        )
        assert license.expires_at is not None
        assert license.days_until_expiry is not None
        assert license.days_until_expiry <= 30

    def test_create_license_with_notes(self, license_manager):
        """Test license creation with notes."""
        license = license_manager.create_license(
            email="noted@example.com",
            plan=PlanType.PRO,
            notes="Special customer"
        )
        assert license.notes == "Special customer"

    def test_validate_valid_license(self, license_manager):
        """Test validating a valid license."""
        created = license_manager.create_license(
            email="valid@example.com",
            plan=PlanType.PRO
        )
        validated = license_manager.validate(created.license_key)
        assert validated is not None
        assert validated.email == created.email

    def test_validate_invalid_format(self, license_manager):
        """Test validating invalid format returns None."""
        result = license_manager.validate("invalid-key")
        assert result is None

    def test_validate_nonexistent_license(self, license_manager):
        """Test validating nonexistent license returns None."""
        result = license_manager.validate("MIESC-ABCD-1234-EFAB-5678")
        assert result is None

    def test_validate_expired_license(self, license_manager):
        """Test validating expired license."""
        # Create a license that expires in 1 day
        license = license_manager.create_license(
            email="expired@example.com",
            plan=PlanType.FREE,
            expires_days=1
        )
        # Manually expire the license by setting expires_at in the past
        from datetime import timedelta
        expired_date = datetime.utcnow() - timedelta(days=30)
        updated = license_manager.update_license(
            license.license_key,
            expires_at=expired_date
        )
        # Should return None for expired license or have EXPIRED status
        result = license_manager.validate(license.license_key)
        assert result is None or result.status == LicenseStatus.EXPIRED

    def test_get_license(self, license_manager):
        """Test getting license info without validation."""
        created = license_manager.create_license(
            email="get@example.com",
            plan=PlanType.STARTER
        )
        retrieved = license_manager.get_license(created.license_key)
        assert retrieved is not None
        assert retrieved.license_key == created.license_key

    def test_get_license_invalid(self, license_manager):
        """Test getting nonexistent license."""
        result = license_manager.get_license("MIESC-DEAD-BEEF-CAFE-BABE")
        assert result is None

    def test_list_licenses_all(self, license_manager):
        """Test listing all licenses."""
        # Create some licenses
        license_manager.create_license(email="list1@example.com", plan=PlanType.FREE)
        license_manager.create_license(email="list2@example.com", plan=PlanType.PRO)

        licenses = license_manager.list_licenses()
        assert len(licenses) >= 2

    def test_list_licenses_by_status(self, license_manager):
        """Test listing licenses by status."""
        license_manager.create_license(email="active@example.com", plan=PlanType.FREE)

        active = license_manager.list_licenses(status=LicenseStatus.ACTIVE)
        assert len(active) >= 1
        for lic in active:
            assert lic.status == LicenseStatus.ACTIVE

    def test_list_licenses_by_plan(self, license_manager):
        """Test listing licenses by plan."""
        license_manager.create_license(email="pro@example.com", plan=PlanType.PRO)

        pro_licenses = license_manager.list_licenses(plan=PlanType.PRO)
        assert len(pro_licenses) >= 1
        for lic in pro_licenses:
            assert lic.plan == PlanType.PRO

    def test_list_licenses_by_email(self, license_manager):
        """Test listing licenses by email pattern."""
        license_manager.create_license(email="unique123@test.com", plan=PlanType.FREE)

        results = license_manager.list_licenses(email="unique123")
        assert len(results) >= 1

    def test_update_license_status(self, license_manager):
        """Test updating license status."""
        created = license_manager.create_license(
            email="update@example.com",
            plan=PlanType.FREE
        )
        updated = license_manager.update_license(
            created.license_key,
            status=LicenseStatus.SUSPENDED
        )
        assert updated is not None
        assert updated.status == LicenseStatus.SUSPENDED

    def test_update_license_plan(self, license_manager):
        """Test upgrading license plan."""
        created = license_manager.create_license(
            email="upgrade@example.com",
            plan=PlanType.FREE
        )
        updated = license_manager.update_license(
            created.license_key,
            plan=PlanType.PRO
        )
        assert updated is not None
        assert updated.plan == PlanType.PRO

    def test_update_license_notes(self, license_manager):
        """Test updating license notes."""
        created = license_manager.create_license(
            email="notes@example.com",
            plan=PlanType.FREE
        )
        updated = license_manager.update_license(
            created.license_key,
            notes="Updated notes"
        )
        assert updated is not None
        assert updated.notes == "Updated notes"

    def test_update_nonexistent_license(self, license_manager):
        """Test updating nonexistent license."""
        result = license_manager.update_license(
            "MIESC-DEAD-BEEF-CAFE-BABE",
            status=LicenseStatus.ACTIVE
        )
        assert result is None

    def test_revoke_license(self, license_manager):
        """Test revoking a license."""
        created = license_manager.create_license(
            email="revoke@example.com",
            plan=PlanType.FREE
        )
        result = license_manager.revoke_license(created.license_key)
        assert result is True

        # Verify status
        license = license_manager.get_license(created.license_key)
        assert license.status == LicenseStatus.REVOKED

    def test_revoke_nonexistent_license(self, license_manager):
        """Test revoking nonexistent license."""
        result = license_manager.revoke_license("MIESC-DEAD-BEEF-CAFE-BABE")
        assert result is False

    def test_suspend_license(self, license_manager):
        """Test suspending a license."""
        created = license_manager.create_license(
            email="suspend@example.com",
            plan=PlanType.STARTER
        )
        result = license_manager.suspend_license(created.license_key)
        assert result is True

        license = license_manager.get_license(created.license_key)
        assert license.status == LicenseStatus.SUSPENDED

    def test_reactivate_license(self, license_manager):
        """Test reactivating a suspended license."""
        created = license_manager.create_license(
            email="reactivate@example.com",
            plan=PlanType.PRO
        )
        # First suspend
        license_manager.suspend_license(created.license_key)

        # Then reactivate
        result = license_manager.reactivate_license(created.license_key)
        assert result is True

        license = license_manager.get_license(created.license_key)
        assert license.status == LicenseStatus.ACTIVE

    def test_get_stats(self, license_manager):
        """Test getting license statistics."""
        # Create some licenses
        license_manager.create_license(email="stat1@example.com", plan=PlanType.FREE)
        license_manager.create_license(email="stat2@example.com", plan=PlanType.PRO)

        stats = license_manager.get_stats()
        assert "total" in stats
        assert "active" in stats
        assert "by_plan" in stats
        assert stats["total"] >= 2

    def test_get_stats_by_plan(self, license_manager):
        """Test that stats include all plan types."""
        license_manager.create_license(email="planstat@example.com", plan=PlanType.ENTERPRISE)

        stats = license_manager.get_stats()
        for plan_type in PlanType:
            assert plan_type.value in stats["by_plan"]


# =============================================================================
# Tests for quota_checker.py
# =============================================================================

class TestQuotaChecker:
    """Tests for QuotaChecker class."""

    def test_can_analyze_active_license(self, quota_checker, sample_license):
        """Test can_analyze with active license."""
        # Need to set up the license in the database first
        result = quota_checker.can_analyze(sample_license)
        assert result is True

    def test_can_analyze_inactive_license(self, quota_checker, suspended_license):
        """Test can_analyze with suspended license."""
        result = quota_checker.can_analyze(suspended_license)
        assert result is False

    def test_can_analyze_expired_license(self, quota_checker, expired_license):
        """Test can_analyze with expired license."""
        result = quota_checker.can_analyze(expired_license)
        assert result is False

    def test_can_analyze_enterprise_unlimited(self, quota_checker, enterprise_license):
        """Test can_analyze with enterprise (unlimited) license."""
        result = quota_checker.can_analyze(enterprise_license)
        assert result is True

    def test_can_use_tool_allowed(self, quota_checker, sample_license):
        """Test can_use_tool with allowed tool."""
        # PRO plan allows all tools
        result = quota_checker.can_use_tool(sample_license, "mythril")
        assert result is True

    def test_can_use_tool_not_allowed(self, quota_checker):
        """Test can_use_tool with non-allowed tool."""
        free_license = License(
            id=str(uuid.uuid4()),
            license_key="MIESC-FREE-FREE-FREE-FREE",
            email="free@test.com",
            plan=PlanType.FREE,
            status=LicenseStatus.ACTIVE,
            created_at=datetime.utcnow(),
            max_audits_month=5,
            allowed_tools=["slither", "solhint"],
            ai_enabled=False,
            max_contract_size_kb=50
        )
        result = quota_checker.can_use_tool(free_license, "mythril")
        assert result is False

    def test_can_use_tool_inactive_license(self, quota_checker, suspended_license):
        """Test can_use_tool with inactive license."""
        result = quota_checker.can_use_tool(suspended_license, "slither")
        assert result is False

    def test_can_use_ai_enabled(self, quota_checker, sample_license):
        """Test can_use_ai with AI-enabled plan."""
        result = quota_checker.can_use_ai(sample_license)
        assert result is True

    def test_can_use_ai_disabled(self, quota_checker):
        """Test can_use_ai with plan that doesn't have AI."""
        free_license = License(
            id=str(uuid.uuid4()),
            license_key="MIESC-NOAI-NOAI-NOAI-NOAI",
            email="noai@test.com",
            plan=PlanType.FREE,
            status=LicenseStatus.ACTIVE,
            created_at=datetime.utcnow(),
            ai_enabled=False
        )
        result = quota_checker.can_use_ai(free_license)
        assert result is False

    def test_can_use_ai_inactive(self, quota_checker, suspended_license):
        """Test can_use_ai with inactive license."""
        result = quota_checker.can_use_ai(suspended_license)
        assert result is False

    def test_check_contract_size_valid(self, quota_checker, sample_license):
        """Test check_contract_size with valid size."""
        # PRO plan has 1024KB limit
        result = quota_checker.check_contract_size(sample_license, 500)
        assert result is True

    def test_check_contract_size_too_large(self, quota_checker):
        """Test check_contract_size with oversized contract."""
        free_license = License(
            id=str(uuid.uuid4()),
            license_key="MIESC-SMAL-SMAL-SMAL-SMAL",
            email="small@test.com",
            plan=PlanType.FREE,
            status=LicenseStatus.ACTIVE,
            created_at=datetime.utcnow(),
            max_contract_size_kb=50
        )
        result = quota_checker.check_contract_size(free_license, 100)
        assert result is False

    def test_check_contract_size_unlimited(self, quota_checker, enterprise_license):
        """Test check_contract_size with unlimited plan."""
        result = quota_checker.check_contract_size(enterprise_license, 10000)
        assert result is True

    def test_check_contract_size_inactive(self, quota_checker, suspended_license):
        """Test check_contract_size with inactive license."""
        result = quota_checker.check_contract_size(suspended_license, 10)
        assert result is False

    def test_record_audit(self, quota_checker, sample_license):
        """Test recording an audit."""
        result = quota_checker.record_audit(sample_license)
        assert result is True

    def test_get_usage(self, quota_checker, sample_license):
        """Test getting usage info."""
        usage = quota_checker.get_usage(sample_license)
        assert "month" in usage
        assert "audits_used" in usage
        assert "audits_limit" in usage
        assert "plan" in usage

    def test_get_remaining_audits(self, quota_checker, sample_license):
        """Test getting remaining audits."""
        remaining = quota_checker.get_remaining_audits(sample_license)
        assert remaining >= 0

    def test_get_remaining_audits_unlimited(self, quota_checker, enterprise_license):
        """Test getting remaining audits for unlimited plan."""
        remaining = quota_checker.get_remaining_audits(enterprise_license)
        assert remaining == -1

    def test_filter_tools_all_allowed(self, quota_checker, sample_license):
        """Test filter_tools when all are allowed."""
        requested = ["slither", "mythril", "echidna"]
        allowed = quota_checker.filter_tools(sample_license, requested)
        assert set(allowed) == set(requested)

    def test_filter_tools_some_blocked(self, quota_checker):
        """Test filter_tools when some are blocked."""
        free_license = License(
            id=str(uuid.uuid4()),
            license_key="MIESC-FLTR-FLTR-FLTR-FLTR",
            email="filter@test.com",
            plan=PlanType.FREE,
            status=LicenseStatus.ACTIVE,
            created_at=datetime.utcnow(),
            allowed_tools=["slither", "solhint"]
        )
        requested = ["slither", "mythril", "echidna"]
        allowed = quota_checker.filter_tools(free_license, requested)
        assert "slither" in allowed
        assert "mythril" not in allowed
        assert "echidna" not in allowed

    def test_filter_tools_inactive_license(self, quota_checker, suspended_license):
        """Test filter_tools with inactive license."""
        requested = ["slither", "mythril"]
        allowed = quota_checker.filter_tools(suspended_license, requested)
        assert allowed == []

    def test_get_current_month(self, quota_checker):
        """Test _get_current_month helper."""
        month = quota_checker._get_current_month()
        assert len(month) == 7  # YYYY-MM format
        assert "-" in month


# =============================================================================
# Integration Tests
# =============================================================================

class TestLicensingIntegration:
    """Integration tests for the licensing system."""

    def test_full_license_lifecycle(self, temp_db_url):
        """Test complete license lifecycle."""
        # Use same DB for both managers
        manager = LicenseManager(database_url=temp_db_url)
        checker = QuotaChecker(database_url=temp_db_url)

        # 1. Create license
        license = manager.create_license(
            email="lifecycle@test.com",
            plan=PlanType.STARTER,
            expires_days=30
        )
        assert license.is_active is True

        # 2. Validate license
        validated = manager.validate(license.license_key)
        assert validated is not None

        # 3. Check quotas
        assert checker.can_analyze(validated) is True
        assert checker.can_use_tool(validated, "slither") is True
        assert checker.can_use_ai(validated) is False  # STARTER doesn't have AI

        # 4. Record audit
        checker.record_audit(validated)
        usage = checker.get_usage(validated)
        assert usage["audits_used"] == 1

        # 5. Suspend license
        manager.suspend_license(license.license_key)
        suspended = manager.get_license(license.license_key)
        assert suspended.status == LicenseStatus.SUSPENDED
        assert checker.can_analyze(suspended) is False

        # 6. Reactivate
        manager.reactivate_license(license.license_key)
        reactivated = manager.get_license(license.license_key)
        assert reactivated.status == LicenseStatus.ACTIVE
        assert checker.can_analyze(reactivated) is True

        # 7. Upgrade plan
        manager.update_license(license.license_key, plan=PlanType.PRO)
        upgraded = manager.get_license(license.license_key)
        assert upgraded.plan == PlanType.PRO
        assert checker.can_use_ai(upgraded) is True

        # 8. Revoke
        manager.revoke_license(license.license_key)
        revoked = manager.get_license(license.license_key)
        assert revoked.status == LicenseStatus.REVOKED

    def test_quota_limits_enforcement(self, temp_db_url):
        """Test that quota limits are enforced."""
        manager = LicenseManager(database_url=temp_db_url)
        checker = QuotaChecker(database_url=temp_db_url)

        # Create FREE license with 5 audits/month limit
        license = manager.create_license(
            email="quota@test.com",
            plan=PlanType.FREE
        )

        # Use up the quota
        for i in range(5):
            assert checker.can_analyze(license) is True
            checker.record_audit(license)

        # 6th audit should be blocked
        assert checker.can_analyze(license) is False

        # Check remaining
        remaining = checker.get_remaining_audits(license)
        assert remaining == 0

    def test_tool_access_by_plan(self, temp_db_url):
        """Test tool access varies by plan."""
        manager = LicenseManager(database_url=temp_db_url)
        checker = QuotaChecker(database_url=temp_db_url)

        # Create licenses for different plans
        free = manager.create_license(email="free@test.com", plan=PlanType.FREE)
        starter = manager.create_license(email="starter@test.com", plan=PlanType.STARTER)
        pro = manager.create_license(email="pro@test.com", plan=PlanType.PRO)

        # FREE: only slither, solhint
        assert checker.can_use_tool(free, "slither") is True
        assert checker.can_use_tool(free, "mythril") is False

        # STARTER: more tools including mythril
        assert checker.can_use_tool(starter, "mythril") is True
        assert checker.can_use_tool(starter, "certora") is False

        # PRO: all tools
        assert checker.can_use_tool(pro, "certora") is True
        assert checker.can_use_tool(pro, "smartllm") is True


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_license_without_expiration(self, license_manager):
        """Test creating perpetual license."""
        license = license_manager.create_license(
            email="perpetual@test.com",
            plan=PlanType.ENTERPRISE,
            expires_days=None
        )
        assert license.expires_at is None
        assert license.is_expired is False
        assert license.days_until_expiry is None

    def test_normalize_key_with_various_formats(self):
        """Test key normalization with various inputs."""
        # Lowercase
        assert normalize_key("miesc-abcd-1234-efab-5678") == "MIESC-ABCD-1234-EFAB-5678"

        # Mixed case
        assert normalize_key("Miesc-AbCd-1234-EfAb-5678") == "MIESC-ABCD-1234-EFAB-5678"

        # With spaces
        assert normalize_key(" MIESC-ABCD-1234-EFAB-5678 ") == "MIESC-ABCD-1234-EFAB-5678"

    def test_multiple_usage_records_per_license(self, temp_db_url):
        """Test that usage is tracked per month."""
        manager = LicenseManager(database_url=temp_db_url)
        checker = QuotaChecker(database_url=temp_db_url)

        license = manager.create_license(email="monthly@test.com", plan=PlanType.FREE)

        # Record some audits
        checker.record_audit(license)
        checker.record_audit(license)

        usage = checker.get_usage(license)
        assert usage["audits_used"] == 2

    def test_create_license_exception_handling(self, license_manager):
        """Test that exceptions during creation are handled."""
        # This should work normally
        license = license_manager.create_license(
            email="exception@test.com",
            plan=PlanType.FREE
        )
        assert license is not None

    def test_update_license_invalid_key_format(self, license_manager):
        """Test updating with invalid key format."""
        result = license_manager.update_license(
            "not-a-valid-key",
            status=LicenseStatus.ACTIVE
        )
        assert result is None

    def test_filter_tools_empty_list(self, quota_checker, sample_license):
        """Test filter_tools with empty list."""
        allowed = quota_checker.filter_tools(sample_license, [])
        assert allowed == []
