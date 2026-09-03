from .models import AuditLog

def get_client_ip(request) -> str | None:
    if request is None:
        return None
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or None
    return request.META.get("REMOTE_ADDR") or None

def log_event(
    actor,
    action: str,
    target=None,
    metadata: dict = None,
    ip_address: str = None,
    request=None,
) -> AuditLog:
    if ip_address is None:
        ip_address = get_client_ip(request)
    return AuditLog.objects.create(
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        action=action,
        target_type=type(target).__name__ if target is not None else "",
        target_id=str(getattr(target, "pk", "")) if target is not None else "",
        metadata=metadata or {},
        ip_address=ip_address,
    )
