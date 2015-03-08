import unittest

from tornado.httpclient import HTTPRequest
from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.web import Application, HTTPError, RequestHandler

from cors import (
    errors,
    preflight,
    utils,
)
from cors.clients.tornado import (
    WrappedClient,
    normalize_request,
)


class Handler(RequestHandler):
    def handler(self):
        if self.get_argument("error", False):
            raise HTTPError(502)
        headers = self.get_arguments("header")
        headers = [h.split(":") for h in headers]
        [self.set_header(h, v) for h, v in headers]
        self.finish()

    delete = head = get = post = put = options = handler


class Function_normalize_request_Tests(unittest.TestCase):
    def test_request_as_keyword_arguments(self):
        request = normalize_request("foo", headers={"bar": "baz"})

        self.assertIsInstance(request, HTTPRequest)
        self.assertEqual(request.headers["bar"], "baz")

    def test_request_as_HTTPRequest_object(self):
        request = HTTPRequest("foo")

        normalized = normalize_request(request)

        self.assertIs(request, normalized)


class Function_fetch_Tests(AsyncHTTPTestCase):
    def setUp(self):
        super(Function_fetch_Tests, self).setUp()
        self.http_client = WrappedClient()

    def get_app(self):
        return Application([
            (r"/.*", Handler)
        ])

    @gen_test
    def test_no_preflight_needed(self):
        request = HTTPRequest(
            url=self.get_url(
                "/"
                "?header=Access-Control-Allow-Origin:*"
            ),
            headers={
                "Host": "localhost",
                "Origin": self.get_url("/")
            })

        response = yield self.http_client.fetch(request)

        self.assertIsInstance(response.headers, utils.ProtectedHTTPHeaders)

    @gen_test
    def test_preflight_request_failed(self):
        request = HTTPRequest(
            url=self.get_url(
                "/"
                "?header=Access-Control-Allow-Origin:*"
                "&error=true"
            ),
            headers={
                "Content-Type": "application/json",
                "Host": "foo",
                "Origin": "foo",
                "foobar": "baz"
            },
            method="POST",
            body="")

        with self.assertRaises(errors.AccessControlError) as context:
            yield self.http_client.fetch(request)

        self.assertEqual(context.exception.message, "Pre-flight check failed")

    @gen_test
    def test_preflight_checks_fail(self):
        request = HTTPRequest(
            url=self.get_url(
                "/"
                "?header=Access-Control-Allow-Headers:Bar"
                "&header=Access-Control-Allow-Origin:*"
            ),
            headers={
                "foo": "bar",
                "Bar": "baz",
                "Host": "foo",
                "Origin": "foo"
            })

        with self.assertRaises(errors.AccessControlError) as context:
            yield self.http_client.fetch(request)

        self.assertRegexpMatches(
            context.exception.message,
            "Headers set(.*'foo'.*) not allowed")

    @gen_test
    def test_successful_request(self):
        request = HTTPRequest(
            self.get_url(
                "/"
                "?header=Access-Control-Allow-Origin:*"
                "&header=Access-Control-Allow-Method:POST"
            ),
            method="POST",
            body="foo",
            headers={
                "Origin": "foo",
                "Host": "foobar"
            }
        )

        response = yield self.http_client.fetch(request)

        self.assertEqual(response.code, 200)

    @gen_test
    def test_send_with_expected_server_error(self):
        self.http_client.skip_checks_on_server_error = True
        request = HTTPRequest(
            self.get_url("/?header=Access-Control-Allow-Origin:*&error=true"),
            method="HEAD",
            headers={
                "Host": "localhost",
                "Origin": self.get_url("")
            })

        response = yield self.http_client.fetch(request, raise_error=False)

        self.assertEqual(response.code, 502)
