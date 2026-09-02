"""
moderation/logging_service.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

Central write path for moderation.models.AuditLog. Other apps should call
`log_event` rather than creating AuditLog rows directly, so the schema can
evolve in one place (e.g. once real request IP capture / structured
metadata is added).

TODO(Mos. Mahabuba Akter Munia):
    - Capture real client IP (request.META handling, proxy-aware).
    - Call this from accounts/views.py (login/logout/2FA events), posts/views.py
      (post create/delete, Afnan's), social/views.py (comment delete, yours),
      and this app's own admin/developer actions (account state changes via
      user_management()/manage_users(), admin-role grants via
      manage_admins(), session revocation - all yours; Razeen only owns the
      dashboard() shell and portal_login()).
"""

from .models import AuditLog


def log_event(actor, action: str, target=None, metadata: dict = None, ip_address: str = None) -> AuditLog:
    return AuditLog.objects.create(
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        action=action,
        target_type=type(target).__name__ if target is not None else "",
        target_id=str(getattr(target, "pk", "")) if target is not None else "",
        metadata=metadata or {},
        ip_address=ip_address,
    )
