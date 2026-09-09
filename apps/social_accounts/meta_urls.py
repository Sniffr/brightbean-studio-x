"""Meta callback URLs - not auth-protected, CSRF-exempt.

Kept out of ``social_accounts.urls`` because everything in there is
workspace-scoped and login-required; these are the opposite by requirement.
Mounted at ``/webhooks/meta/`` alongside the inbox webhook receivers.
"""

from django.urls import path

from . import meta_callbacks

app_name = "social_accounts_meta"

urlpatterns = [
    path("deauthorize/", meta_callbacks.deauthorize_callback, name="deauthorize"),
    path("data-deletion/", meta_callbacks.data_deletion_callback, name="data_deletion"),
    path(
        "data-deletion/status/<str:confirmation_code>/",
        meta_callbacks.data_deletion_status,
        name="data_deletion_status",
    ),
]
