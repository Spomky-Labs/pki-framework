# Public Key Infrastructure

> [!NOTE]
> This framework started as a fork of the libraries published at https://github.com/sop. It has diverged
> substantially since — the code has been reworked, extended and maintained to meet the Spomky-Labs requirements —
> and the two are no longer interchangeable. All credits for the original work go to its developer.

A PHP Framework

* X.509 public key certificates, attribute certificates,
* X.690 Abstract Syntax Notation One (ASN.1) Distinguished Encoding Rules (DER) encoding and decoding
* X.501 ASN.1 types, X.520 attributes and DN parsing.
* [RFC 7468](https://tools.ietf.org/html/rfc7468) textual encodings of cryptographic structures _(PEM)_.
* Various ASN.1 types for cryptographic applications.
* Cryptography support for various PKCS applications.

## Requirements

- PHP >=8.1
- `mbstring`

The extension `gmp` or `bcmath` is highly recommended

## Installation

This library is distributed on [Packagist](https://packagist.org/packages/spomky-labs/pki-framework); the source lives
on [GitHub](https://github.com/Spomky-Labs/pki-framework).

```sh
composer require spomky-labs/pki-framework
```

## Issuing certificates from a certification request

`TBSCertificate::fromCSR()` builds a certificate from a certification request. **Everything a certification request
contains is chosen by whoever submitted it**, so an issuer must treat it as untrusted input:

- the signature of the request is **not** verified by `fromCSR()`. Call `CertificationRequest::verify()` yourself
    before using it;
- extensions that decide what a certificate is allowed to do — `basicConstraints`, `keyUsage`, `extKeyUsage`,
    `nameConstraints`, `policyConstraints`, `policyMappings`, `inhibitAnyPolicy`, `certificatePolicies` and
    `authorityKeyIdentifier` — are never copied from the request. They belong to the issuer, which sets them with
    `withExtensions()` / `withAdditionalExtensions()`;
- every other requested extension **is** copied, `subjectAltName` included. Pass the OIDs the issuer is willing to
    honour as the second argument to restrict the copy:

```php
$tbsCertificate = TBSCertificate::fromCSR($csr, [Extension::OID_SUBJECT_ALT_NAME]);
```

## Validating a certification path

The trust anchor is an input to the validation process, never something read out of the material the peer sent. Start
from the certificates you trust and let the library build the path to the target:

```php
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

$trustAnchors = CertificateBundle::create($rootA, $rootB); // your trust store
$intermediates = CertificateBundle::create(...$chainFromPeer); // untrusted, used only to bridge the path

$path = CertificationPath::toTarget($leafFromPeer, $trustAnchors, $intermediates);

try {
    $result = $path->validate(PathValidationConfig::defaultConfig());
} catch (PathValidationException $e) {
    // the chain does not lead to any certificate you trust
}
```

If you already hold the path, name the anchor explicitly:

```php
$config = PathValidationConfig::defaultConfig()->withTrustAnchor($root);
$path->validate($config);
```

Do not validate a chain a peer supplied without an anchor. Left to itself, validation would fall back to the first
certificate of the path — one the peer chose — and confirm only that the chain is internally consistent. A path built
by `CertificationPath::fromCertificateChain()` refuses to validate without an explicit anchor for that reason.

## Security

Path validation checks that a chain is well-formed and leads to a trust anchor you named. It does **not** check
revocation: the library never contacts a CRL distribution point or an OCSP responder, so a revoked certificate still
validates. Revocation is the calling application's responsibility.

Found a vulnerability? Do not open a public issue — read [SECURITY.md](SECURITY.md) and report it privately.

## License

This project is licensed under the MIT License.
