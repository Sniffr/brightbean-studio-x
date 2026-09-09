"""Tearing down a connected account, independent of who asked for it.

The disconnect *view* used to own this logic, which made it unreachable from
anywhere without a ``request``: Meta's deauthorize and data-deletion callbacks
arrive unauthenticated, carrying a signed platform user ID and no session at
all. The steps are identical either way, so they live here and the view is now
one caller among several.

Ordering matters and is not obvious: webhooks are unsubscribed *before* the
token is revoked, because unsubscribing is itself an authenticated call.
"""

import logging

from django.db.models import Count

from .provider_factory import _get_provider_for_platform
from .webhooks import unsubscribe_account_webhooks

logger = logging.getLogger(__name__)


def teardown_account(account) -> str:
    """Unsubscribe, revoke, drop orphaned posts, and delete ``account``.

    Returns the account's display name for the caller's message. Best-effort by
    design: a provider that refuses the revoke must not strand the row, since
    the user has already asked for it to be gone.
    """
    # Stop the platform pushing us this account's activity before we drop the
    # token that would let us unsubscribe.
    if account.oauth_access_token:
        unsubscribe_account_webhooks(account)

    try:
        provider = _get_provider_for_platform(account.platform, account.workspace.organization_id)
        if account.oauth_access_token:
            provider.revoke_token(account.oauth_access_token)
    except Exception:
        logger.warning(
            "Failed to revoke token for %s, proceeding with disconnect",
            account,
        )

    # Delete posts that ONLY target this account (will be fully orphaned).
    # Multi-platform posts keep their other PlatformPost targets via cascade.
    from apps.composer.models import PlatformPost, Post

    orphan_post_ids = list(
        PlatformPost.objects.filter(social_account=account)
        .values("post_id")
        .annotate(total_platforms=Count("post__platform_posts"))
        .filter(total_platforms=1)
        .values_list("post_id", flat=True)
    )
    if orphan_post_ids:
        Post.objects.filter(id__in=orphan_post_ids).delete()

    account_name = account.account_name or account.account_handle
    account.delete()
    return account_name
