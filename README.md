# AIA Chaser

[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-darkgoldenrod.svg)](https://opensource.org/licenses/MIT)
[![Linter: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)


This package aims to provide authority information access (AIA) chasing
from a host/leaf certificate to complete its chain of trust and generate
an SSL context to establish a secure connection.

## Overview

AIA, an extension of the X509 standard in
[RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280),
points a client towards two types of endpoints:
  * CA Issuers: To fetch the *issuer* certificate.
  * OSCP: To check the certificate's revocation status.

Thanks to this information, it is possible to complete the chain of trust
of a certificate. Without AIA chasing, some HTTPS requests may fail if
the endpoint does not provide all the certificates of its chain of trust.

You may have experienced that already when some HTTPS URL works on your
browser but fail when using `curl` or `Python` + `requests`. Then this
package could be of help to you :guide_dog:.

## Examples

The following examples showcase how to use this library with some typical
Python HTTP libraries.

  * Standard library's **urlopen**:

```Python
from urllib.request import urlopen
from aia_chaser import AiaChaser

url = "https://..."

chaser = AiaChaser()
context = chaser.make_ssl_context_for_url(url)
response = urlopen(url, context=context)
```

  * Using [Requests: HTTP for Humans](https://docs.python-requests.org/en/latest/index.html):

```Python
import requests
from aia_chaser import AiaChaser

chaser = AiaChaser()
url = "https://www.mediatek.com/"
context = chaser.make_ssl_context_for_url(url)

ca_data = chaser.fetch_ca_chain_for_url(url)
with tempfile.NamedTemporaryFile("wt") as pem_file:
    pem_file.write(ca_data.to_pem())
    pem_file.flush()
    response = requests.get(url, verify=pem_file.name)
```

  * Using [urllib3](https://urllib3.readthedocs.io/en/stable/):

```Python
import urllib3
from aia_chaser import AiaChaser

url = "https://..."

chaser = AiaChaser()
context = chaser.make_ssl_context_for_url(url)
with urllib3.PoolManager(ssl_context=context) as pool:
    respone = pool.request("GET", url)
```

## Development

First of all, you must have the following tools installed and on
your `$PATH`.

 * [Pyenv](https://github.com/pyenv/pyenv)
 * [Poetry](https://python-poetry.org/docs/#installation)
 * Make

Then, open a terminal on the project's directory and run:

```console
make init
```

## Acknowledgments

* This project is based on [aia](https://github.com/danilobellini/aia).
