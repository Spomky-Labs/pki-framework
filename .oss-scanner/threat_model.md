# Threat model

This file steers the [OSS Scanner](https://github.com/anthropics/oss-scanner). Vulnerabilities found by other means
are reported as described in [SECURITY.md](../SECURITY.md).

## What this project does

`spomky-labs/pki-framework` is a PHP library, with no framework dependency, that decodes, builds and validates the
structures of a public key infrastructure:

- `src/ASN1`: the ASN.1 decoder and encoder (X.690). It reads DER and the indefinite length form of BER, and refuses
    the non-minimal encodings DER forbids, so that a parsed certificate re-encodes to the bytes it arrived as.
- `src/CryptoEncoding`: PEM blocks and bundles (RFC 7468).
- `src/CryptoTypes`: algorithm identifiers, public and private keys (RSA, EC, the RFC 8410 curves) and signature
    values.
- `src/CryptoBridge`: the signature and cipher engine, `OpenSSLCrypto`, built on ext-openssl, with ext-sodium for
    Ed25519 where the OpenSSL extension has no EdDSA.
- `src/X501`: distinguished names, their comparison after the string preparation of RFC 4518 (`StringPrep`,
    `MatchingRule`) and their RFC 2253 string form (`DN/DNParser`).
- `src/X509`: certificates, certification requests (PKCS #10), attribute certificates (RFC 5755), extensions and
    general names, the certification path builder (RFC 4158), the path validator (RFC 5280 section 6) and the
    attribute certificate validator.

The library never opens a network connection and reads no system trust store: everything it trusts is handed to it by
the calling application. Among others, `web-auth/webauthn-lib` uses it to parse the attestation certificates and the
ASN.1 extensions an authenticator sends during a WebAuthn registration, and to validate their chains against the trust
anchors of the FIDO metadata service. That material is controlled by the attacker until it chains to a trust anchor.

## Where untrusted input enters

The attacker is whoever produces the bytes an application hands to the library: a peer presenting a certificate chain,
an authenticator, a requester submitting a certification request, the holder or issuer of an attribute certificate.
Untrusted input:

- Every DER, BER or PEM input: `Element::fromDER()`, `UnspecifiedType::fromDER()` and the `fromDER()` of each ASN.1
    type, `PEM::fromString()`, `PEMBundle::fromString()`, `CertificateChain::fromPEMString()`, and the `fromDER()` and
    `fromPEM()` of `Certificate`, `CertificationRequest`, `AttributeCertificate` and `PublicKeyInfo`.
- Everything inside a certificate before its path is validated: names, validity, public key, signature value and
    extensions, including the raw value of an unknown extension (`UnknownExtension::extensionValue()`), which callers
    decode with `Sequence::fromDER()`.
- The certificates of a path other than the trust anchor: the intermediate bundle passed to
    `CertificationPath::toTarget()`, the chain passed to `CertificationPath::fromCertificateChain()`, and the target.
- The names compared during path building and validation (`Name::equals()`, `NameConstraintsMatcher`).
- Certification requests passed to `TBSCertificate::fromCSR()`: everything in them is chosen by the requester.
- Attribute certificates, and the holder and issuer paths that come with them, passed to `ACValidator`.
- Distinguished names in string form (`Name::fromString()`) when the application takes them from users.

What is trusted:

- The trust anchors: the bundle passed to `CertificationPath::toTarget()` and the certificate set with
    `PathValidationConfig::withTrustAnchor()`. The trust anchor is an input to the validation, never something read
    out of the material the peer sent.
- The configuration: `PathValidationConfig` (reference time, maximum length, policy set, allowed signature algorithms,
    minimum RSA key size, additional critical extensions, legacy v1 intermediates), `ACValidationConfig` (trusted
    attribute authorities, targets), `Element::setMaxNestingDepth()` and the extension allow list of
    `TBSCertificate::fromCSR()`. An insecure default is a vulnerability. An insecure value that the application has to
    set explicitly, and that the docblock flags, is not.
- The private keys of the application and the certificates it issues with them (`TBSCertificate::sign()`), and the
    `Crypto` engine it passes in.
- PHP and its extensions, OpenSSL, libsodium and `brick/math`.

## Security properties that must hold

- Malformed input makes the parsers throw an exception that `catch (Exception)` catches: `Element::fromDER()` reports
    it as a `DecodeException`, no `Error` (`TypeError`, `ValueError`) escapes any parser, and no input crashes the
    process.
- The cost of parsing and validation stays proportionate to the input. Nesting depth is capped
    (`Element::DEFAULT_MAX_NESTING_DEPTH`), base-128 fields are capped, path building is bounded by the limits of
    `CertificationPathBuilder` and the policy tree by `PolicyTree`. A few kilobytes must not cost seconds of CPU or
    unbounded memory.
- A signed object has a single accepted encoding: certificates, certification requests and attribute certificates must
    be DER with no trailing bytes, the signature is verified over the bytes received
    (`src/X509/Feature/SignedDER.php`), and `Certificate::equals()` compares those bytes.
- Fields are read as the specifications define them, so that the library and other implementations agree on what a
    certificate says: a repeated extension or tagged field is refused rather than merged, named bits of a BIT STRING,
    UTCTime years, IP addresses and their masks are decoded as RFC 5280 defines them.
- `PathValidator` accepts a path only when it starts at the trust anchor the application named; every signature
    verifies with the issuer's key, under an allowed algorithm and with an RSA key no smaller than the minimum; every
    certificate is within its validity period at the reference time; issuer and subject names chain; every CA
    certificate is a v3 certificate with `basicConstraints` cA, and with keyCertSign when it carries `keyUsage` (v1
    and v2 only when the configuration trusts them); path length, name constraints and policy constraints hold; and
    every critical extension is one the validator processes or one the application declared. A name constraint of a
    form the validator cannot evaluate makes the validation fail.
- A path built by `CertificationPath::fromCertificateChain()` never validates without an explicit trust anchor, and
    every path returned by `CertificationPathBuilder` is headed by a certificate from the trust list it was given.
- Two names compare equal exactly when RFC 5280 section 7.1 and RFC 4518 say they do. A name that cannot be prepared
    for comparison fails the validation or the path building; it is never reported as "not equal".
- `ACValidator` accepts an attribute certificate only when the holder and issuer paths validate, its signature
    verifies under the same algorithm and key size policy as the path, the issuer is not a CA and, when configured, is
    a trusted attribute authority, it is within its validity period, its targeting matches, and it carries no critical
    extension the validator does not process.
- `TBSCertificate::fromCSR()` never copies the extensions of `TBSCertificate::FORBIDDEN_CSR_EXTENSIONS` nor an unknown
    critical extension, and copies only the allow list when one is given.
- A predicate such as `Certificate::verify()` returns false rather than throwing on a signature it cannot check, and
    verification fails closed when the runtime cannot verify the algorithm.
- `withRandomSerialNumber()` draws at least 64 bits of entropy.

## Components that matter most

- `src/X509/CertificationPath`: `PathValidator`, `ValidatorState`, `NameConstraintsMatcher`, `PolicyTree` and
    `PolicyNode`, `CertificationPathBuilder` and `CertificationPath`.
- The ASN.1 decoder: `Element::fromDER()`, `Component/Identifier`, `Component/Length`, `Type/Structure`, the tagged
    types and the primitives (`ObjectIdentifier`, `Integer`, `BitString`, `Real`, `UTCTime`, `GeneralizedTime` and the
    string types).
- `src/X509/Certificate`: `Certificate`, `TBSCertificate` (`fromASN1()`, `fromCSR()`), `Extensions`, the extension
    classes that drive validation (`BasicConstraintsExtension`, `KeyUsageExtension`, `NameConstraintsExtension`, the
    policy extensions), `Time` and `Validity`; `src/X509/GeneralName`; `src/X509/Feature/SignedDER.php`.
- `src/X501`: `Name`, `RDN`, `AttributeTypeAndValue`, the matching rules and the string preparation.
- `src/X509/AttributeCertificate`, its `Validation` directory included.
- `OpenSSLCrypto`, the signature values (`ECSignature` first) and the decoding of public keys in `src/CryptoTypes`.
- The PEM regular expression (`PEM::PEM_REGEX`), shared by `PEM` and `PEMBundle`.

Less important but in scope: certificate and request building, the cipher functions of `OpenSSLCrypto`, the decoding
of private keys, `DNParser` and the string representations. Deprecated code paths are in scope as long as they ship.

## How to exercise it

The image has PHP 8.3 with the gmp, bcmath, openssl, sodium, intl and mbstring extensions, and the dependencies
installed in `vendor/`. Run the tests as the CI does:

    vendor/bin/phpunit
    vendor/bin/phpunit --testsuite X509
    vendor/bin/phpunit --filter NameConstraintsEnforcementTest

Four tests are skipped in this image: the OpenSSL extension of PHP 8.3 has no EdDSA and ext-sodium covers Ed25519
only, so Ed448 signatures cannot be verified and their verification fails closed, as documented.

- `tests/ASN1/Regression`, `tests/X501/Regression` and `tests/X509/Regression` hold one test class per fixed issue.
    `tests/X509/Integration/PathValidation` drives `PathValidator` over whole paths. A reproducer goes in one of them.
- `tests/assets` holds certificates and keys (`TEST_ASSETS_DIR`, defined in `tests/bootstrap.php`). Most regression
    tests build and sign their own certificates with `TBSCertificate::sign()` and the keys of
    `tests/assets/certs/keys` (see `tests/X509/Regression/PathBuildingBoundTest.php`); raw DER can be written as a
    string literal (see `tests/ASN1/Regression/DerMinimalityTest.php`).
- For a cost finding, give the size of the input, the time or memory it takes in this image, and how that grows with
    the size.

## How we rate severity

- Critical: path validation accepts a certificate for an identity or a use that its issuers did not grant, in the
    default configuration with an explicit trust anchor, with nothing more than the certificates an ordinary
    subscriber can obtain; or executing code or accessing files through the processing of untrusted input.
- High: a path or attribute certificate validation bypass that needs a realistic precondition, such as a certificate
    from a constrained or delegated sub-CA, a v1 certificate issued by a trusted CA, a name the matcher does not
    canonicalise, a critical extension that should have stopped the validation, or a field read differently from other
    implementations in a way that grants a privilege (cA, keyCertSign, extensions); a requester obtaining more from
    `fromCSR()` than the issuer meant to grant; a validation policy set by the configuration (allowed algorithms,
    minimum key size) that does not apply on some path; a few kilobytes of unauthenticated input costing seconds of
    CPU or more, unbounded memory, or a crash of the process, before any trust check.
- Medium: more than one accepted encoding for a signed object, or another parser differential that does not grant a
    privilege on its own; an issuer's restriction dropped, or a weak algorithm the application cannot refuse; an
    exception outside the documented contract; a cost issue that needs a correctly signed chain from a delegated
    sub-CA, that a stock PHP limit caps, or that costs a fraction of a second per operation.
- Low: a weakness in issuance with no demonstrated bypass (serial numbers); missing syntax validation with no
    demonstrated bypass; duplicate handling that diverges from other implementations without granting anything; a date
    decoded wrongly that needs a certificate already signed with that date.

For calibration, the published advisories were rated as follows:

- Critical: GHSA-3p3r-m556-g5px, name constraints never enforced during path validation.
- High: GHSA-vw7q-hxmh-m835, v1 and v2 certificates accepted as intermediate CAs; GHSA-mxjh-6r54-88x9, the first
    certificate of the chain treated as the trust anchor; GHSA-v76j-9ghr-85fr, unrecognized critical extensions
    ignored; GHSA-mh5j-7xj5-9h45, name constraints evaded by a trailing dot and by URI parser differences;
    GHSA-6chf-2x6r-fjhg, iPAddress names encoding a different address; GHSA-2rhj-2r69-j232, name comparison defeated
    by the string type and by invisible characters; GHSA-9hcj-84c7-2pj8, a second extensions element replacing the
    first; GHSA-gjx8-fvx6-qg7q, keyUsage bits read from the wrong end of an over-long BIT STRING; GHSA-5474-45mw-c3xq,
    `fromCSR()` copying the extensions that make a CA; GHSA-85g4-f9rx-c6ww, attribute certificate signatures exempt
    from the algorithm and key size policy; GHSA-v473-mx2x-xqpv, quadratic decoding of tag numbers, OID
    sub-identifiers and REAL mantissas; GHSA-rfxw-c9pp-xvfw and GHSA-c67f-8q64-6hxh, unbounded path building;
    GHSA-xjj7-24gw-437v, unbounded recursion in the decoder.
- Medium: GHSA-f28f-xc9q-m482, signature verified over a re-encoded TBSCertificate; GHSA-mx53-vr97-rxr2, ECDSA
    signature values re-encoded before verification; GHSA-5gp6-jr6q-ffx7, no way to refuse MD4, MD5 and SHA-1;
    GHSA-6pj8-5pjp-gj6w, unsupported critical extensions of attribute certificates ignored; GHSA-jj8p-rwmj-6rjj, a
    `TypeError` escaping `catch (Exception)`; GHSA-34rx-vp5j-q2wr, policy tree growth through a signed chain from a
    delegated sub-CA; GHSA-x673-qv99-7268, cubic backtracking of the PEM regular expression; GHSA-894f-9q28-7w2x,
    costly comparison of multi-valued RDNs.
- Low: GHSA-8qrh-8g3j-pxvv, weak default serial numbers; GHSA-6q28-45jq-2628, NUL bytes in dNSName and rfc822Name;
    GHSA-wc4q-rp39-hwpf, duplicate extensions merged; GHSA-j49g-8r6c-p7w2, wrong century for UTCTime years 50 to 69.

## Anything to leave alone

- Bugs in PHP, its extensions, OpenSSL, libsodium and `brick/math`: they are separate projects.
- `tests/`, `.github/`, the QA configuration (`ecs.php`, `rector.php`, `phpstan.neon`, `infection.json.dist`) and the
    development dependencies. Findings there are welcome as ordinary issues.
- What the README and SECURITY.md leave to the application: revocation (no CRL or OCSP is ever fetched), the choice
    of the trust anchor, the signature of a certification request passed to `fromCSR()`
    (`CertificationRequest::verify()`), and RFC 5755 section 5 check 4 when no trusted attribute authority is
    configured. The purpose of the end-entity certificate (`extendedKeyUsage`) is not part of the RFC 5280 path
    validation either: the application checks it on the validated certificate.
- Compatibility defaults that the docblocks flag and that come with a hardened alternative: SHA-1 and 1024-bit RSA in
    the default policy (`HARDENED_ALLOWED_SIGNATURE_ALGORITHMS`, `HARDENED_MINIMUM_RSA_KEY_SIZE`), the deprecated
    fallback of a path built by `CertificationPath::create()` to its first certificate, and `fromCSR()` called without
    an allow list. Both deprecated behaviours raise a deprecation notice. A report is useful when it gets past what
    these guards promise, not when it restates them.
- Insecure values the application sets explicitly: `withLegacyV1IntermediatesTrusted(true)`,
    `withMinimumRSAKeySize(0)`, a weak algorithm passed to `withAllowedSignatureAlgorithms()`,
    `withAdditionalCriticalExtensions()`, a large `Element::setMaxNestingDepth()`.
- Ed448 (and Ed25519 without ext-sodium) not being verifiable on a runtime whose OpenSSL extension has no EdDSA: the
    verification fails closed, as documented.

## Reports

Include a reproducer written as a PHPUnit test in one of the directories above, the configuration it needs when it is
not the default one, and a patch against the scanned branch. The maintainers port the fix to the supported release
line.
