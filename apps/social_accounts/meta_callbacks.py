"""Meta's deauthorize and data-deletion callbacks.

Meta requires every app to expose two unauthenticated endpoints: one it pings
when a person removes the app, and one it pings when they ask for their data to
be deleted. Both are POSTed as a ``signed_request`` — an HMAC-SHA256 envelope
carrying the person's *app-scoped user ID* — with no session, no cookie and no
workspace, which is why they cannot reuse the workspace-scoped disconnect view.

The teardown itself is not new: these hand off to ``teardown_account``, the same
path the in-app Disconnect button takes. What is new is only the bridge from
Meta's identity to ours.

One URL serves all three Meta app identities (Facebook/Instagram, Instagram
Login, Threads). Which app sent a given request is decided by *which configured
app secret verifies the signature*, exactly as inbound webhooks decide it in
``apps.inbox.webhooks``, and the teardown is then scoped to that app's platforms
and to orgs whose own secret signed it — so one org's secret can never delete
another org's accounts.
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets as secrets_mod

from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from django_ratelimit.decorators import ratelimit

from apps.credentials.models import PlatformCredential, resolve_app_secret, resolve_app_secrets

from .models import MetaDataDeletionRequest, SocialAccount
from .teardown import teardown_account

logger = logging.getLogger(__name__)

# Every platform that authenticates against a Meta app. Facebook and Instagram
# (Facebook Login) share one app and therefore one secret; Instagram Direct and
# Threads each have their own.
META_PLATFORMS = (
    PlatformCredential.Platform.FACEBOOK,
    PlatformCredential.Platform.INSTAGRAM,
    PlatformCredential.Platform.INSTAGRAM_LOGIN,
    PlatformCredential.Platform.THREADS,
)


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, restoring the padding Meta strips."""
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _secrets_by_platform() -> dict[str, set[str]]:
    """Map each Meta platform to every app secret that could sign for it.

    ``resolve_app_secrets`` flattens across platforms, which is right for
    "is this signature valid at all" but loses the mapping we need to answer
    "and which platforms does that app cover".
    """
    return {platform: set(resolve_app_secrets(platform)) for platform in META_PLATFORMS}


def _parse_signed_request(
    signed_request: str, secrets_by_platform: dict[str, set[str]]
) -> tuple[dict, str] | tuple[None, None]:
    """Verify ``signed_request`` against configured Meta secrets and decode it.

    Returns ``(payload, signing_secret)``, or ``(None, None)`` if nothing
    verifies. The secret comes back because the caller needs it to decide which
    app — and so which platforms and which orgs — the request speaks for.
    """
    try:
        encoded_sig, encoded_payload = signed_request.split(".", 1)
        expected_sig = _b64url_decode(encoded_sig)
        payload = json.loads(_b64url_decode(encoded_payload))
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        logger.warning("Meta callback: malformed signed_request.")
        return None, None

    if not isinstance(payload, dict):
        logger.warning("Meta callback: signed_request payload is not an object.")
        return None, None

    # Meta documents HMAC-SHA256 as the only algorithm. Refusing anything else
    # keeps a forged payload from naming a weaker one.
    if payload.get("algorithm", "").upper() != "HMAC-SHA256":
        logger.warning("Meta callback: unsupported signed_request algorithm %r.", payload.get("algorithm"))
        return None, None

    for platform_secrets in secrets_by_platform.values():
        for secret in platform_secrets:
            computed = hmac.new(secret.encode(), encoded_payload.encode(), hashlib.sha256).digest()
            if hmac.compare_digest(computed, expected_sig):
                return payload, secret

    logger.warning("Meta callback: signature did not match any configured app secret.")
    return None, None


def _platforms_for_secret(signing_secret: str, secrets_by_platform: dict[str, set[str]]) -> list[str]:
    """Platforms belonging to the Meta app whose secret signed the request."""
    return [platform for platform, secrets in secrets_by_platform.items() if signing_secret in secrets]


def _accounts_for(platform_user_id: str, signing_secret: str, platforms: list[str]):
    """Accounts this signed request is entitled to act on.

    Two narrowings, both load-bearing. The signing app's platforms, so a Threads
    deauthorization cannot reach a Facebook Page; and, per account, the org's
    *own* resolved secret must be the one that signed — the same binding
    ``_process_meta_events`` applies to inbound events.
    """
    if not platforms:
        return []

    candidates = SocialAccount.objects.filter(
        platform__in=platforms,
        platform_user_id=platform_user_id,
    ).select_related("workspace__organization")

    entitled = []
    for account in candidates:
        account_secret = resolve_app_secret(account.platform, account.workspace.organization_id)
        if account_secret and hmac.compare_digest(account_secret, signing_secret):
            entitled.append(account)
        else:
            logger.warning(
                "Meta callback: signature not valid for account %s's org app; skipping.",
                account.id,
            )
    return entitled


def _read_signed_request(request):
    """Pull ``signed_request`` out of a callback POST, form or JSON."""
    signed_request = request.POST.get("signed_request", "")
    if signed_request:
        return signed_request
    try:
        return json.loads(request.body or b"{}").get("signed_request", "")
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        return ""


@csrf_exempt
@ratelimit(key="ip", rate="60/m", block=True)
@require_POST
def deauthorize_callback(request):
    """Meta pings this when someone removes the app from their account.

    Their grant is already gone on Meta's side, so the connection here is dead
    whatever we do; tearing it down is what stops the app showing a channel that
    can no longer publish. Always answers 200 — Meta retries on anything else,
    and there is nothing a retry would fix.
    """
    secrets_by_platform = _secrets_by_platform()
    payload, signing_secret = _parse_signed_request(_read_signed_request(request), secrets_by_platform)
    if payload is None:
        return HttpResponseForbidden("Invalid signed_request.")

    platform_user_id = str(payload.get("user_id") or "")
    if not platform_user_id:
        # Without an ID there is nobody to deauthorize, and matching the blank
        # string would sweep up every account connected before platform_user_id
        # was recorded.
        logger.warning("Meta deauthorize: signed_request carried no user_id.")
        return HttpResponse("OK", status=200)

    platforms = _platforms_for_secret(signing_secret, secrets_by_platform)
    for account in _accounts_for(platform_user_id, signing_secret, platforms):
        try:
            teardown_account(account)
        except Exception:
            logger.exception("Meta deauthorize: teardown failed for account %s", account.id)

    return HttpResponse("OK", status=200)


@csrf_exempt
@ratelimit(key="ip", rate="60/m", block=True)
@require_POST
def data_deletion_callback(request):
    """Meta pings this when someone asks for their data to be deleted.

    Deletes the same way disconnecting does — tokens revoked, webhooks
    unsubscribed, accounts and their orphaned posts removed — then answers with
    the confirmation code and status URL Meta requires. A malformed or unsigned
    request is the one case that gets a 4xx: there is no code to hand back.
    """
    secrets_by_platform = _secrets_by_platform()
    payload, signing_secret = _parse_signed_request(_read_signed_request(request), secrets_by_platform)
    if payload is None:
        return HttpResponseForbidden("Invalid signed_request.")

    platform_user_id = str(payload.get("user_id") or "")
    if not platform_user_id:
        logger.warning("Meta data deletion: signed_request carried no user_id.")
        return HttpResponseForbidden("signed_request carried no user_id.")

    platforms = _platforms_for_secret(signing_secret, secrets_by_platform)
    confirmation_code = secrets_mod.token_hex(16)

    deleted = 0
    failures = []
    for account in _accounts_for(platform_user_id, signing_secret, platforms):
        account_id = account.id
        try:
            teardown_account(account)
            deleted += 1
        except Exception:
            logger.exception("Meta data deletion: teardown failed for account %s", account_id)
            failures.append(str(account_id))

    if failures:
        status = MetaDataDeletionRequest.Status.FAILED
        detail = f"{len(failures)} account(s) could not be deleted: {', '.join(failures)}"
    elif deleted:
        status = MetaDataDeletionRequest.Status.COMPLETED
        detail = ""
    else:
        status = MetaDataDeletionRequest.Status.NOTHING_TO_DELETE
        detail = ""

    MetaDataDeletionRequest.objects.create(
        confirmation_code=confirmation_code,
        platform=platforms[0] if platforms else "",
        platform_user_id=platform_user_id,
        status=status,
        accounts_deleted=deleted,
        detail=detail,
    )

    return JsonResponse(
        {
            "url": request.build_absolute_uri(
                reverse("social_accounts_meta:data_deletion_status", args=[confirmation_code])
            ),
            "confirmation_code": confirmation_code,
        }
    )


@require_GET
@ratelimit(key="ip", rate="30/m", block=True)
def data_deletion_status(request, confirmation_code):
    """The page Meta's confirmation code points at.

    Unauthenticated by necessity — the person following it has just severed the
    only link between us — so the 32-hex code is the whole of the access
    control, and a wrong one must be indistinguishable from an expired one.
    """
    deletion_request = get_object_or_404(MetaDataDeletionRequest, confirmation_code=confirmation_code)
    return render(
        request,
        "social_accounts/data_deletion_status.html",
        {"deletion_request": deletion_request},
    )
