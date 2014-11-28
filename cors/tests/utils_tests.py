import unittest

from cors.errors import AccessControlError
from cors.utils import ProtectedHTTPHeaders

class ProtectedHTTPHeadersTests(unittest.TestCase):
    def setUp(self):
        self.headers = {
            "Content-Length": "20",
            "Foo-Bar": "foobar",
            "Content-Type": "application/json"
        }
        self.protected = ProtectedHTTPHeaders(
            ("foo-bar", "x-auth-token"),
            self.headers
        )

    def test_get_simple_response_header(self):
        content_type = self.protected["Content-Type"]
        self.assertEqual(content_type, "application/json")

    def test_get_simple_header_case_irrelevant(self):
        content_type = self.protected["content-type"]
        self.assertEqual(content_type, "application/json")

    def test_get_non_simple_header(self):
        foo_bar = self.protected["foo-bar"]
        self.assertEqual(foo_bar, "foobar")

    def test_get_non_simple_unexposed_header(self):
        with self.assertRaises(AccessControlError) as context:
            _ = self.protected["Content-Length"]

        self.assertIn("not allowed", context.exception.message)

    def test_exposed_unset_header(self):
        token = self.protected.get("X-Auth-Token", "aaaa-bbbb-ccc-dddd")
        self.assertEqual(token, "aaaa-bbbb-ccc-dddd")

    def test_initialize_with_header_string(self):
        protected = ProtectedHTTPHeaders(
            "foo-bar, x-auth-token",
            self.headers)

        self.assertEqual(protected["foo-bar"], "foobar")
        with self.assertRaises(AccessControlError) as context:
            _ = protected["Content-Length"]

        self.assertIn("not allowed", context.exception.message)

