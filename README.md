# AIA Chaser

[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![Linter: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-darkgoldenrod.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)


This library provides a mechanism to chase authority information access (AIA)
fields from a host/leaf certificate to complete its chain of trust and,
finally, generate an SSL context to establish a secure connection.

## Overview

AIA is an extension of the X509 standard in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)
and it points a client towards two types of endpoints:
  * CA Issuers: To fetch the *issuer* certificate.
  * OSCP: To check the certificate's revocation status.

Thanks to this information it is possible to build the complete chain
of trust of a certificate.

## Examples

The following examples showcase how to use this library with some typical Python HTTP libraries.

**TODO**

## Acknowledgments

* This project is based on [aia](https://github.com/danilobellini/aia).
