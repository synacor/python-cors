from __future__ import absolute_import

import unittest

import mock

from cors.clients import requests
from cors import (
    errors,
    preflight,
    utils
)


def _request(url="http://example.com", method="GET", headers=None, origin="http://example.com", **kwargs):
    request = mock.MagicMock(name="mock_request")
    request._response = mock.MagicMock()
    request.kwargs = {"_response": request._response}
    request.kwargs.update(kwargs)
    request.url = url
    request.method = method
    request.headers = utils.HeadersDict(headers or {})
    request.prepare = lambda: request

    if "origin" not in request.headers:
        request.headers["origin"] = origin
    return request

def _response(request=None, headers=None):
    response = mock.MagicMock()
    response.request = request or _request()
    response.headers = utils.HeadersDict(headers or {})
    return response

def _session():
    session = mock.MagicMock()
    def send_(request):
        return getattr(request, "_response", mock.MagicMock())
    session.send = mock.MagicMock(wraps=send_)
    return session


class Function_send_Tests(unittest.TestCase):

    @mock.patch("cors.clients.requests.prepare_preflight")
    def test_no_preflight_needed(self, prepare):
        prepare.return_value = (None, [])
        request = _request()

        response = requests.send(request, _session())

        self.assertIsInstance(response.headers, utils.ProtectedHTTPHeaders)

    @mock.patch("requests.Request", wraps=_request)
    @mock.patch("cors.clients.requests.prepare_preflight")
    def test_preflight_request_failed(self, prepare, _):
        response = _response()
        response.ok = False
        prepare.return_value = (_request(), [])
        session = mock.MagicMock()
        session.send.return_value = response
        request = _request(
            url="http://example.com/",
            headers={"Content-Type": "application/json"},
            method="POST")

        with self.assertRaises(errors.AccessControlError) as context:
            requests.send(request, session)

        self.assertEqual(context.exception.message, "Pre-flight check failed")

    @mock.patch("requests.Request", wraps=_request)
    @mock.patch("cors.clients.requests.prepare_preflight")
    def test_preflight_checks_fail(self, prepare, _):
        check_a = mock.MagicMock()
        check_b = mock.MagicMock(side_effect=errors.AccessControlError("foo"))
        prepare.return_value = (_request(), [check_a, check_b])
        request = _request()

        with self.assertRaises(errors.AccessControlError) as context:
            requests.send(request, _session())
            self.assertTrue(check_b.call_count > 0)

        self.assertEqual(context.exception.message, "foo")
        self.assertEqual(check_a.call_count, 1)

    @mock.patch("requests.Request", wraps=_request)
    @mock.patch("cors.clients.requests.prepare_preflight")
    def test_successful_request(self, prepare, _):
        check = mock.MagicMock()
        preflight_request = _request()
        prepare.return_value = (preflight_request, [check])
        request = _request()
        session = _session()

        response = requests.send(request, session)

        self.assertEqual(session.send.call_count, 2)
        self.assertEqual(response, request._response)

    @mock.patch("requests.Request", wraps=_request)
    @mock.patch("cors.clients.requests.prepare_preflight")
    def test_send_with_expected_server_error(self, prepare, _):
        check = preflight.check_headers
        prepare.return_value = (None, [check])
        request = _request()
        request._response = _response()
        request._response.status_code = 500
        request._response.headers["Access-Control-Allow-Headers"] = "foo"
        session = _session()

        response = requests.send(
            request,
            session,
            skip_checks_on_server_error=True)

        self.assertEqual(response.status_code, 500)
        self.assertNotIn(
            "Content-Type",
            response.headers["Access-Control-Allow-Headers"])
