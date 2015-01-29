from __future__ import absolute_import

from tornado.concurrent import Future
from tornado.gen import coroutine, Return
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

from cors.errors import AccessControlError
from cors.preflight import check_origin, prepare_preflight
from cors.utils import ProtectedHTTPHeaders


def enforce_cors_on_client(client):
    client._original_fetch = client.fetch
    client.fetch = cors_enforced_fetch.__get__(client, AsyncHTTPClient)


def normalize_request(request, **kwargs):
    if not isinstance(request, HTTPRequest):
        request = HTTPRequest(url=request, **kwargs)
    return request


def safe_fetch(fetch, request):
    future = Future()
    fetch(request, callback=future.set_result)
    return future


@coroutine
def cors_enforced_fetch(client, request, callback=None, raise_error=True, **kwargs):
    fetch = getattr(client, "_original_fetch", client.fetch)
    request = normalize_request(request, **kwargs)
    preflight, checks = prepare_preflight(request)

    if preflight is not None:
        preflight = HTTPRequest(
            preflight.url,
            preflight.method,
            preflight.headers)


        response = yield safe_fetch(fetch, preflight)
        if response.error:
            raise AccessControlError(
                "Pre-flight check failed",
                preflight.url,
                preflight.method,
                preflight.headers)

        # check that the preflight response says its ok to send our followup.
        # below check again that the preflight grants access to the response.
        for check in checks:
            check(response, request)

    if raise_error:
        response = yield fetch(request)
    else:
        response = yield safe_fetch(fetch, request)

    # double-check that the actual response included appropriate headers as well
    # skip checks in the case of a server error unless configured otherwise.
    skip_checks = getattr(client, "skip_checks_on_server_error", False)
    if response.code / 100 != 5 or not skip_checks:
        check_origin(response, request)

    # wrap the headers in a protective layer
    exposed = response.headers.get("Access-Control-Expose-Headers", "")
    response.headers = ProtectedHTTPHeaders(exposed, response.headers)

    if not callable(callback):
        raise Return(response)
    else:
        callback(response)
