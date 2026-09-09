"""Tests for Meta's deauthorize and data-deletion callbacks."""

import base64
import hashlib
import hmac
import json
from unittest.mock import patch

import pytest
from django.urls import reverse

from apps.social_accounts.models import MetaDataDeletionRequest, SocialAccount

FB_SECRET = "fb-secret"
THREADS_SECRET = "threads-secret"

# Facebook and Instagram share one Meta app; Threads has its own.
META_ENV = {
    "facebook": {"app_secret": FB_SECRET},
    "instagram": {"app_secret": FB_SECRET},
    "threads": {"app_secret": THREADS_SECRET},
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def signed_request(secret: str, **payload) -> str:
    """Build a signed_request the way Meta does."""
    payload.setdefault("algorithm", "HMAC-SHA256")
    encoded_payload = _b64url(json.dumps(payload).encode())
    signature = hmac.new(secret.encode(), encoded_payload.encode(), hashlib.sha256).digest()
    return f"{_b64url(signature)}.{encoded_payload}"


@pytest.fixture
def workspace(db, organization):
    from apps.workspaces.models import Workspace

    return Workspace.objects.create(name="Test WS", organization=organization)


@pytest.fixture
def fb_account(db, workspace):
    """A Facebook Page connected by the person whose ASID is ``asid-1``."""
    return SocialAccount.objects.create(
        workspace=workspace,
        platform="facebook",
        account_platform_id="page-1",
        platform_user_id="asid-1",
        account_name="Brightbean Page",
        oauth_access_token="page-token",
    )


@pytest.fixture(autouse=True)
def _meta_app_configured(settings):
    """Configure the Meta app secrets and keep teardown off the wire.

    ``override_settings`` cannot decorate a plain pytest class, so the env
    credentials are installed here alongside the patches that stop
    ``teardown_account`` revoking tokens and unsubscribing webhooks for real.
    """
    settings.PLATFORM_CREDENTIALS_FROM_ENV = META_ENV
    with (
        patch("apps.social_accounts.teardown.unsubscribe_account_webhooks"),
        patch("apps.social_accounts.teardown._get_provider_for_platform"),
    ):
        yield


@pytest.mark.django_db
class TestDeauthorizeCallback:
    def setup_method(self):
        self.url = reverse("social_accounts_meta:deauthorize")

    def test_valid_request_deletes_the_account(self, client, fb_account):
        response = client.post(self.url, {"signed_request": signed_request(FB_SECRET, user_id="asid-1")})

        assert response.status_code == 200
        assert not SocialAccount.objects.filter(id=fb_account.id).exists()

    def test_unsigned_request_is_rejected(self, client, fb_account):
        response = client.post(self.url, {"signed_request": "deadbeef.eyJ1c2VyX2lkIjoiYXNpZC0xIn0"})

        assert response.status_code == 403
        assert SocialAccount.objects.filter(id=fb_account.id).exists()

    def test_signature_from_another_meta_app_does_not_reach_this_platform(self, client, fb_account):
        """Threads' secret is valid, but only for Threads accounts."""
        response = client.post(self.url, {"signed_request": signed_request(THREADS_SECRET, user_id="asid-1")})

        assert response.status_code == 200
        assert SocialAccount.objects.filter(id=fb_account.id).exists()

    def test_a_different_user_is_untouched(self, client, fb_account):
        response = client.post(self.url, {"signed_request": signed_request(FB_SECRET, user_id="asid-999")})

        assert response.status_code == 200
        assert SocialAccount.objects.filter(id=fb_account.id).exists()

    def test_missing_user_id_does_not_sweep_up_unrecorded_accounts(self, client, workspace):
        """Rows connected before platform_user_id existed have it blank.

        A callback with no user_id must not match them by empty-string equality.
        """
        legacy = SocialAccount.objects.create(
            workspace=workspace,
            platform="facebook",
            account_platform_id="page-legacy",
            platform_user_id="",
            account_name="Legacy Page",
        )

        response = client.post(self.url, {"signed_request": signed_request(FB_SECRET)})

        assert response.status_code == 200
        assert SocialAccount.objects.filter(id=legacy.id).exists()

    def test_forged_algorithm_is_refused(self, client, fb_account):
        encoded_payload = _b64url(json.dumps({"algorithm": "none", "user_id": "asid-1"}).encode())
        response = client.post(self.url, {"signed_request": f"{_b64url(b'x')}.{encoded_payload}"})

        assert response.status_code == 403
        assert SocialAccount.objects.filter(id=fb_account.id).exists()

    def test_get_is_not_allowed(self, client):
        assert client.get(self.url).status_code == 405


@pytest.mark.django_db
class TestDataDeletionCallback:
    def setup_method(self):
        self.url = reverse("social_accounts_meta:data_deletion")

    def test_deletes_and_returns_meta_s_required_shape(self, client, fb_account):
        response = client.post(self.url, {"signed_request": signed_request(FB_SECRET, user_id="asid-1")})

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"url", "confirmation_code"}
        assert not SocialAccount.objects.filter(id=fb_account.id).exists()

        record = MetaDataDeletionRequest.objects.get(confirmation_code=body["confirmation_code"])
        assert record.status == MetaDataDeletionRequest.Status.COMPLETED
        assert record.accounts_deleted == 1
        # The URL Meta hands the user has to actually resolve here.
        assert body["url"].endswith(
            reverse("social_accounts_meta:data_deletion_status", args=[body["confirmation_code"]])
        )

    def test_records_a_request_with_nothing_to_delete(self, client):
        response = client.post(self.url, {"signed_request": signed_request(FB_SECRET, user_id="nobody")})

        assert response.status_code == 200
        record = MetaDataDeletionRequest.objects.get(confirmation_code=response.json()["confirmation_code"])
        assert record.status == MetaDataDeletionRequest.Status.NOTHING_TO_DELETE
        assert record.accounts_deleted == 0

    def test_unsigned_request_gets_no_confirmation_code(self, client, fb_account):
        response = client.post(self.url, {"signed_request": "deadbeef.eyJ1c2VyX2lkIjoiYXNpZC0xIn0"})

        assert response.status_code == 403
        assert not MetaDataDeletionRequest.objects.exists()
        assert SocialAccount.objects.filter(id=fb_account.id).exists()

    def test_accepts_a_json_body(self, client, fb_account):
        """Meta posts form-encoded, but the field has been seen as JSON too."""
        response = client.post(
            self.url,
            data=json.dumps({"signed_request": signed_request(FB_SECRET, user_id="asid-1")}),
            content_type="application/json",
        )

        assert response.status_code == 200
        assert not SocialAccount.objects.filter(id=fb_account.id).exists()

    def test_a_failed_teardown_is_recorded_not_swallowed(self, client, fb_account):
        with patch(
            "apps.social_accounts.meta_callbacks.teardown_account",
            side_effect=RuntimeError("provider down"),
        ):
            response = client.post(self.url, {"signed_request": signed_request(FB_SECRET, user_id="asid-1")})

        assert response.status_code == 200
        record = MetaDataDeletionRequest.objects.get(confirmation_code=response.json()["confirmation_code"])
        assert record.status == MetaDataDeletionRequest.Status.FAILED
        assert str(fb_account.id) in record.detail


@pytest.mark.django_db
class TestDataDeletionStatusPage:
    def test_shows_the_request_for_a_valid_code(self, client):
        record = MetaDataDeletionRequest.objects.create(
            confirmation_code="abc123",
            platform="facebook",
            platform_user_id="asid-1",
            status=MetaDataDeletionRequest.Status.COMPLETED,
            accounts_deleted=2,
        )

        response = client.get(reverse("social_accounts_meta:data_deletion_status", args=[record.confirmation_code]))

        assert response.status_code == 200
        assert b"abc123" in response.content

    def test_unknown_code_is_a_404(self, client):
        response = client.get(reverse("social_accounts_meta:data_deletion_status", args=["nope"]))

        assert response.status_code == 404
