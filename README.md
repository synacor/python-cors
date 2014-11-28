# CORS

> A Python package for dealing with HTTP requests and same-origin policies.


## Overview

This package was developed to improve automated HTTP API tests by being able to
automatically test that any requests we make can also be made from browsers with
scripts on other origins.

The code in this package strives to be mostly agnostic to the library you are
using to actually make the HTTP requests and thus mostly deals in an internally
defined `Request` class which simply contains the url, headers, and method as
properties. From here you can convert to whatever you need to send the request.

Of course, Python programmers tend to love the hell out of 
[_requests_](https://github.com/kennethreitz/requests) (and, I mean, 
who doesn't?), so there's also an included function you can use to send a
request including preflight and CORS header checks.


## Usage

### Low-level

For maximum flexibility you can use the package's low-level functionality to 
generate a preflight request and callable check methods to validate your
request.

```python

import requests
import cors.preflight
import cors.utils

# create my own request
request = requests.Request(
    "POST", "http://example.com",
    headers={"Content-Type": "application/json"},
    body="{}").prepare()

# generate any required preflight and validation checks
preflight, checks = cors.preflight.prepare_preflight(request)

# if a preflight was needed, send it and check its response
if preflight:
    response = requests.request(
        preflight.method,
        preflight.url,
        preflight.headers)

    # any failed check will raise cors.errors.AccessControlError
    for check in checks:
        check(response, request)

# must be OK.
response = requests.Session().send(request.prepare())

# check again that the actual response agrees with the preflight
for check in checks:
    check(response, request)

# We can also enforce access to the response headers.
# Now whenever we try to use a head which was not explicitly exposed by the CORS
# response headers, or is not a "simple response header" an AccessControlError
# is raised.
response.headers = cors.utils.ProtectedHTTPHeaders(
    response.headers.get("Access-Control-Allow-Headers", ""),
    response.headers)

```

The intention here is for you to write a suitable wrapper which accepts requests
in whatever form works best for your HTTP client library.

But for many people that library is `requests`, so...


### Using with requests

```python

import requests
import cors.preflight

my_request = requests.Request(
    "POST", "http://example.com",
    headers={"Content-Type": "application/json"},
    body="{}").prepare()

response = cors.preflight.send(my_request)

```

Done. The `cors.preflight.send` function will inspect your prepared request
object and:

1. generate and send a preflight request if necessary
2. pick and run any necessary validation checks
3. wrap the response headers in a `ProtectedHTTPHeaders` instance.

When calling `send` you may also include a custom requests.Session instance, and
a flag to specify that CORS checks on the actual request should be if the server
comes back with a `5XX` error.
