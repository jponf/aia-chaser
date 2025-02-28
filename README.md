# AIA Chaser

[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-darkgoldenrod.svg)](https://opensource.org/licenses/MIT)
[![Linter: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

[
![PyPI - Version](https://img.shields.io/pypi/v/aia-chaser)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aia-chaser)
](https://pypi.org/project/aia-chaser/)

[![Read the Docs](https://img.shields.io/readthedocs/aia-chaser)](https://aia-chaser.readthedocs.io)


This package helps automatically retrieve missing certificates to complete a secure SSL chain of trust. It ensures that even if a server doesn’t provide the full certificate chain, your connection remains secure.

## What is AIA Chasing?

AIA (Authority Information Access) is a feature in SSL certificates, defined in
[RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280), that points to:

 - CA Issuers – To fetch missing issuer certificates.
 - OCSP – To check if a certificate has been revoked.

By following these links, this package helps fill in the gaps, ensuring your
SSL connections don’t fail due to missing certificates.

## Why Does This Matter?

Sometimes, a website works fine in your browser but fails when using `curl` or
Python’s `requests` library. That is because browsers often handle AIA chasing
automatically, while other tools don’t. If you’ve run into SSL errors like
this, this package can help! :guide_dog:.

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
url = "https://..."
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

## Acknowledgments

* This project is based on [aia](https://github.com/danilobellini/aia).
