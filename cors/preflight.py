from cors.errors import AccessControlError
from cors.definitions import (
    is_same_origin,
    is_simple_method,
    is_simple_content_type,
    get_prohibited_headers,
)
from cors.utils import (
    CaseInsensitiveDict,
    ProtectedHTTPHeaders,
    Request,
)

def format_header_field(header):
    return "-".join(map(str.capitalize, header.split("-")))

def check_origin(response, prepared_request):
    """
    Assert that a cross origin response allows requests from a request's origin.

    """
    request = prepared_request
    headers = CaseInsensitiveDict(prepared_request.headers)
    if is_same_origin(request):
        return

    origin = headers["origin"]
    if response.headers.get("Access-Control-Allow-Origin") not in ("*", origin):
        raise AccessControlError(
            "Origin %r not allowed for resource %r" % (origin, request.url),
            request.url,
            request.method,
            request.headers)

def check_method(response, prepared_request):
    """
    Assert that the requested method is allowed.

    """
    request = prepared_request

    if is_simple_method(request):
        return

    allowed = response.headers.get("Access-Control-Allow-Methods", "")
    allowed = map(str.strip, allowed.split(","))

    if request.method not in allowed:
        raise AccessControlError(
            "Method %r not allowed for resource %r" % (request.method, request.url),
            request.url,
            request.method,
            request.headers)

def check_headers(response, prepared_request):
    """
    Assert that the requested headers are allowed.

    """
    request = prepared_request
    allowed = response.headers.get("Access-Control-Allow-Headers", "")

    prohibited = get_prohibited_headers(request, allowed)
    if len(prohibited) == 0:
        return

    if prohibited == set(["content-type"]) and is_simple_content_type(request):
        return

    raise AccessControlError(
        "Headers %r not allowed for resource %r" % (prohibited, request.url),
        request.url,
        request.method,
        request.headers)

def prepare_preflight_allowed_origin(request):
    if is_same_origin(request):
        return {}, []
    return {}, [check_origin]

def prepare_preflight_allowed_methods(request):
    headers = {}
    checks = []
    if not is_simple_method(request):
        headers["Access-Control-Allow-Methods"] = request.method
        checks.append(check_method)
    if not is_simple_content_type(request):
        headers["Access-Control-Allow-Headers"] = "Content-Type"
        checks.append(check_headers)

    return headers, checks

def prepare_preflight_allowed_headers(request):
    needed = list(get_prohibited_headers(request, {}))
    needed = map(format_header_field, needed)

    if len(needed) == 0:
        return {}, []

    return (
        {"Access-Control-Allow-Headers": ",".join(needed)},
        [check_headers]
    )

def prepare_preflight(request):
    """
    Generate a preflight request and followup checks.

    """
    headers = {}
    checks = []

    if request.method == "OPTIONS":
        return None, []

    for prep in (
            prepare_preflight_allowed_origin,
            prepare_preflight_allowed_headers,
            prepare_preflight_allowed_methods):
        required_headers, required_checks = prep(request)
        headers.update(required_headers)
        checks.extend(required_checks)

    # It is possible to have only one check (origin) which necessitates sending
    # a preflight request even though it won't include any CORS request headers.
    if len(headers) == 0 and len(checks) == 0:
        return None, []

    headers["Host"] = request.headers.get("host")
    preflight = Request(
        "OPTIONS",
        request.url,
        headers)

    return preflight, checks

def send(request, session=None, skip_checks_on_server_error=True, **kwargs):
    """
    Send a request adhering to same-origin policy rules.

    Heads up; this function uses the requests library because most people do.
    If you intend to use another Python HTTP client, don't use this method

    """
    import requests
    session = session or requests.Session()
    preflight, checks = prepare_preflight(request)

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
        for check in checks:
            check(response, request)

    # wrap the headers in a protective layer
    exposed = response.headers.get("Access-Control-Expose-Headers", "")
    response.headers = ProtectedHTTPHeaders(exposed, response.headers)

    return response
