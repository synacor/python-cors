class CORSError(Exception):
    """Base class for CORS-related errors."""

class AccessControlError(CORSError):
    """Raised when access to the requested resource is not permitted."""
    def __init__(self, message, url=None, method=None, headers=None):
        super(AccessControlError, self).__init__(message)
        self.url = url
        self.method = method
        self.headers = headers
