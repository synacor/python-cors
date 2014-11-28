import unittest

from cors import definitions

class Function_normalize_list_Tests(unittest.TestCase):
    def test_normalize_list(self):
        list_ = "Foo-Bar, Baz, QUX"

        normalized = definitions._normalize_list(list_)

        self.assertEqual(normalized, ["foo-bar", "baz", "qux"])

    def test_normalize_is_idempotent(self):
        list_ = "Foo-bar, Baz, QUX"

        one = definitions._normalize_list(list_)
        two = definitions._normalize_list(one)

        self.assertEqual(one, two)


class Function_normalize_origin_url_Tests(unittest.TestCase):
    def test_url_without_port(self):
        http = "http://foo/bar?baz=qux#quux"
        https = "https://foo/bar?baz=qux#quux"

        http = definitions._normalize_origin_url(http)
        https = definitions._normalize_origin_url(https)

        self.assertEqual(http, "http://foo:80")
        self.assertEqual(https, "https://foo:443")

    def test_url_with_port(self):
        http = "http://foo:8080/foo"
        https = "https://foo:8443/foo"

        http = definitions._normalize_origin_url(http)
        https = definitions._normalize_origin_url(https)

        self.assertEqual(http, "http://foo:8080")
        self.assertEqual(https, "https://foo:8443")
