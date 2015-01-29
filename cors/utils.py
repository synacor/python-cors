from requests.structures import CaseInsensitiveDict

from cors.errors import AccessControlError
from cors.definitions import (
    CORS_RESPONSE_HEADERS,
    SIMPLE_RESPONSE_HEADERS,
)

class ProtectedHTTPHeaders(CaseInsensitiveDict):
    """
    Protective layer to limit access to cross origin response headers.

    """
    def __init__(self, exposed_headers, *args, **kwargs):
        super(ProtectedHTTPHeaders, self).__init__(*args, **kwargs)
        self.exposed_headers = exposed_headers
        if isinstance(exposed_headers, basestring):
            exposed_headers = exposed_headers.split(",")
            exposed_headers = map(str.strip, exposed_headers)
        self.exposed_headers = map(str.lower, exposed_headers)

    def check_header_accessible(self, name):
        if name.lower() in SIMPLE_RESPONSE_HEADERS | CORS_RESPONSE_HEADERS:
            return
        if name.lower() not in self.exposed_headers:
            raise AccessControlError("Access to header %r not allowed." % name)

    def __getitem__(self, name):
        self.check_header_accessible(name)
        return super(ProtectedHTTPHeaders, self).__getitem__(name)

    def get(self, name, default=None):
        self.check_header_accessible(name)
        return super(ProtectedHTTPHeaders, self).get(name, default)


class Request(object):
    """
    HTTP library agnostic request class.

    """
    def __init__(self, method, url, headers=None, **kwargs):
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.kwargs = kwargs
