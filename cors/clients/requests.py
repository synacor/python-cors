from __future__ import absolute_import

import requests

from cors.errors import AccessControlError
from cors.utils import ProtectedHTTPHeaders
from cors.preflight import (
    check_origin,
    prepare_preflight,
)


def send(request, session=None, skip_checks_on_server_error=True, **kwargs):
    """
    Send a request adhering to same-origin policy rules.

    Heads up; this function uses the requests library because most people do.
    If you intend to use another Python HTTP client, don't use this method

    """
    session = session or requests.Session()
    preflight, checks = prepare_preflight(request)

    print request
    print preflight, checks

    if preflight is not None:
        preflight = requests.Request(
            preflight.method,
            preflight.url,
            preflight.headers,
            **preflight.kwargs).prepare()

        response = session.send(preflight)
        if not response.ok:
            raise AccessControlError(
                "Pre-flight check failed",
                preflight.url,
                preflight.method,
                preflight.headers)

        # check that the preflight response says its ok to send our followup.
        # below check again that the preflight grants access to the response.
        for check in checks:
            check(response, request)

    response = session.send(request, **kwargs)

    # double-check that the actual response included appropriate headers as well
    # skip checks in the case of a server error unless configured otherwise.
    if response.status_code / 100 != 5 or not skip_checks_on_server_error:
        check_origin(response, request)

    # wrap the headers in a protective layer
    exposed = response.headers.get("Access-Control-Expose-Headers", "")
    response.headers = ProtectedHTTPHeaders(exposed, response.headers)

    return response
