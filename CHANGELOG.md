# Changelog

All notable changes to this project will be documented in this file.

## [3.6.1] - 2026-10-31

### 🚀 Features

- Add optional certifi trust-store support

### 📚 Documentation

- Document certifi trust-store setup and API

### 🧪 Testing

- Use certifi-based fixtures to avoid relying on system trust store
- Disable unauthorized revoked OCSP endpoint

## [3.6.0] - 2026-10-25

### 🚀 Features

- *(aia)* Add allow_private_ip option for OCSP and CRL revocation checks
- *(aia)* Expose configurable certificate download retries
- *(http)* Honor Retry-After headers in HTTP retries
- *(http)* Centralize HTTP-only downloads with retries
- *(cache)* Expire AIA certificates after 12 hours

### 🐛 Bug Fixes

- Increase aiohttp max_line_size/max_field_size if the host returns large headers (e.g. CSP)
- Catch CRL/OCSP download errors in verify_certificate_chain
- Reject file/ftp/data schemes in the certificate opener
- _try_parse_crl tried DER loader twice instead of PEM

### 📚 Documentation

- Clarify that AIA, OCSP, and CRL downloads are limited to HTTP(S)
- *(chaser)* Clarify strict IP policy precedence during verification

### 🧪 Testing

- Make resolver test portable on Windows
- Cover AIA URL rejection and revocation error wrapping

### ⚙️ Miscellaneous Tasks

- Add Python 3.15 to the test matrix

## [3.5.0] - 2026-10-21

### 🚀 Features

- [**breaking**] Drop Python 3.8 support

### 🐛 Bug Fixes

- *(network)* Keep address types compatible with Python 3.9
- *(url)* Handle uppercase schemes consistently
- *(network)* Reject multicast destinations
- *(security)* Pin HTTP connections to validated addresses
- *(http)* Preserve proxy behavior for private IP downloads

### 💼 Other

- Update cryptography

### 🚜 Refactor

- *(network)* Group network related utilities
- *(tests)* Reorganize certificate pinning coverage
- *(chaser)* Cache certificate openers by IP policy

### 📚 Documentation

- *(network)* Clarify address policy errors and inputs
- *(security)* Explain strict address policy and v4 default

### 🧪 Testing

- Strengthen network policy regression coverage
- Expand URL and pinned networking coverage

### ⚙️ Miscellaneous Tasks

- Add pull_request and workflow_call triggers to Python CI
- Split Python checks from main test matrix
- Upgrade checkout and setup-python actions to v7
- Add Python lint and test workflow

## [3.4.1] - 2026-04-26

### 🚀 Features

- Export AiaChaserError and AiaChaserWarning from top-level package

### 🐛 Bug Fixes

- Use 'poetry-core' as build backend
- Skip unparsable trust-store certs and suppress CryptographyDeprecationWarning

### 📚 Documentation

- Add contributing guide

### 🧪 Testing

- Add test data directory and cert_utils tests

### 🏗️ Build

- Add git-cliff config and document changelog generation

## [3.4.0] - 2026-02-28

### 🚀 Features

- Add retry support for OCSP requests
- Expose retry configuration in verification configs
- Add temp_pem_file utility for Windows compatibility

### 🐛 Bug Fixes

- Upgrade cryptography to fix vulnerabilities
- Update httpx version
- Use revocation_date_utc to avoid deprecation warning
- Add User-Agent header to pycurl test for CI compatibility
- Use ssl.PROTOCOL_TLS_CLIENT to avoid deprecation warning
- Use PROTOCOL_TLS_CLIENT with disabled handshake verification

### 📚 Documentation

- Fix requests example and add httpx, aiohttp and pycurl examples

### 🧪 Testing

- Add HTTP library integration tests

### ⚙️ Miscellaneous Tasks

- Add code coverage reporting to pytest
- Improve CI reliability and reduce matrix size

## [3.3.0] - 2025-09-12

### 🐛 Bug Fixes

- Capture urlopen HTTP errors

### 🧪 Testing

- Remove URL that behaves erroneously

## [3.2.0] - 2025-07-23

### 🚀 Features

- Support parsing PKCS7 certificates
- Add support for certificate revocation lists (CRL)

### 🐛 Bug Fixes

- Return in `verify` if iterator is empty


## [3.1.2] - 2025-03-06

### 🚀 Features

- Add trusted certificates to chaser directly
  - Originally only ssl context certificates were trusted

## [3.1.1] - 2025-02-28

### 🐛 Bug Fixes

- Ignore SSLError when loading ca_files

### 📚 Documentation

- Improve readme

## [3.1.0] - 2025-02-24

### 🚀 Features

- Support chasing starting from a certificate
- Try all http/https AIA URLs before failing

## [3.0.0] - 2025-02-21

### 🚀 Features

- Improve OCSP verification

### 📚 Documentation

- Fix docstrings

## [2.0.0] - 2025-02-18

### 🚀 Features

- Add OCSP verification and improve verify_certificate_chain interface
- Remove content type validation as parsing will check it anyway
- Support turning verification on/off and configuring its behavior

### 🚜 Refactor

- Extracted methods that can be used in other modules to a common file
- Rename exceptions

### 📚 Documentation

- Add docs and improve pydocstrings
- Add readthedocs configuration
- Add logo and favicon
- Moved development section to a separate file

### 🧪 Testing

- Increase number of URLs in test
- Add expired and ocsp revoked tests

## [1.2.0] - 2025-02-13

### 🚀 Features

- New supported content-type application/octet-stream
- Root CA fingerprint validation

### 💼 Other

- Modify project setup scripts and update dependencies

### 🚜 Refactor

- Fix linter errors in tests/
- Fix linter errors in aia_chaser/utils/

### ⚙️ Miscellaneous Tasks

- Update ruff configuration
- Update github workflow

## [1.1.0] - 2024-01-24

### 🚀 Features

- Add CertificatesChain class with convenient methods to_der/to_pem
- Try parse in PEM format if DER fails.

### 🐛 Bug Fixes

- New supported content-type binary/octet-stream
- Use offset-aware datetime to verify validity period

<!-- generated by git-cliff -->
