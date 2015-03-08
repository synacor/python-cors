from cors.errors import AccessControlError
from cors.definitions import (
    CORS_RESPONSE_HEADERS,
    SIMPLE_RESPONSE_HEADERS,
)


class HeadersDict(dict):
    """
    A dictionary that translates keys to HTTP header case.

    """
    def __init__(self, *args, **kwargs):
        super(HeadersDict, self).__init__(*args, **kwargs)

    @staticmethod
    def normalize(key):
        return "-".join(map(str.capitalize, key.split("-")))

    def __getitem__(self, key):
        return super(HeadersDict, self).__getitem__(self.normalize(key))

    def __setitem__(self, key, value):
        return super(HeadersDict, self).__setitem__(self.normalize(key), value)

    def __delitem__(self, key):
        return super(HeadersDict, self).__delitem__(self.normalize(key))

    def __contains__(self, key):
        return super(HeadersDict, self).__contains__(self.normalize(key))


class ProtectedHTTPHeaders(HeadersDict):
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
