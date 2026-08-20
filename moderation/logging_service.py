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
      and this app's own admin actions (role changes, account state changes,
      session revocation - Razeen's admin panel / your admin sub-pages).
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
