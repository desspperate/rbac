from fastapi import Request


def get_request_metadata(request: Request) -> tuple[str, str]:
    user_agent = request.headers.get("User-Agent", "")
    ip_address = (
        request.headers.get("X-Real-IP")
        or _first_forwarded_ip(request.headers.get("X-Forwarded-For"))
        or (request.client.host if request.client else "")
    )
    return user_agent, ip_address


def _first_forwarded_ip(forwarded_for: str | None) -> str:
    if not forwarded_for:
        return ""
    return forwarded_for.split(",")[0].strip()
