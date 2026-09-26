class HttpError(Exception):
    def __init__(self, status_code: int, message: str, code: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class UnauthorizedError(HttpError):
    def __init__(self, message: str = "Missing or invalid bearer token") -> None:
        super().__init__(401, message, "unauthorized")


class ForbiddenError(HttpError):
    def __init__(self, message: str) -> None:
        super().__init__(403, message, "forbidden")


class AuthError(Exception):
    pass


class JwksUnavailableError(Exception):
    """Not an AuthError: an upstream/infra failure, not a verdict about the token, so
    require_auth must not translate it into a 401."""


class UpstreamError(Exception):
    pass


class AuthConfigError(Exception):
    pass
