<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410;

use function array_key_exists;
use function function_exists;
use function is_string;
use LogicException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use function sprintf;
use function strlen;

/**
 * Derives the public key of an RFC 8410 private key that does not embed it.
 *
 * PKCS #8 makes the public key optional, and OpenSSL leaves it out by default, so most Ed25519 and Ed448 keys found
 * in the wild carry only the private part. ext-sodium derives Curve25519 keys directly. Everything else, and
 * Curve25519 where ext-sodium is missing, goes through the OpenSSL extension.
 *
 * @internal
 *
 * @see https://tools.ietf.org/html/rfc8410#section-7
 */
final class PublicKeyDerivation
{
    /**
     * A known private and public key pair per algorithm, used to probe whether the OpenSSL extension derives that
     * algorithm's public key correctly.
     *
     * Ed25519 and Ed448 are RFC 8032 sections 7.1 (TEST 1) and 7.4 (-----Blank), X25519 and X448 are Alice's keys
     * from RFC 7748 sections 6.1 and 6.2.
     *
     * @var array<string, array{private: string, public: string}>
     */
    private const PROBE_VECTORS = [
        AlgorithmIdentifier::OID_ED25519 => [
            'private' => '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
            'public' => 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        ],
        AlgorithmIdentifier::OID_X25519 => [
            'private' => '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
            'public' => '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
        ],
        AlgorithmIdentifier::OID_ED448 => [
            'private' => '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3' .
                '528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
            'public' => '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778' .
                'edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
        ],
        AlgorithmIdentifier::OID_X448 => [
            'private' => '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5' .
                '74a9419744897391006382a6f127ab1d9ac2d8c0a598726b',
            'public' => '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb' .
                'c836647241d953d40c5b12da88120d53177f80e532c41fa0',
        ],
    ];

    /**
     * Whether the OpenSSL extension derives the public key, per algorithm OID.
     *
     * @var array<string, bool>
     */
    private static array $opensslSupport = [];

    /**
     * Derive the raw public key from the raw private key.
     *
     * @param AlgorithmIdentifierType $algo Key algorithm
     * @param string $privateKey Raw private key, the content of `CurvePrivateKey`
     *
     * @throws LogicException If this runtime cannot derive the public key
     */
    public static function derive(AlgorithmIdentifierType $algo, string $privateKey): string
    {
        $publicKey = self::viaSodium($algo, $privateKey) ?? self::viaOpenSSL($algo, $privateKey);
        if ($publicKey === null) {
            throw new LogicException(sprintf(
                'Public key not set and this PHP runtime cannot derive it from the %s private key: ' .
                'that needs ext-sodium (Ed25519 and X25519 only) or an OpenSSL extension supporting the algorithm.',
                $algo->name()
            ));
        }
        return $publicKey;
    }

    /**
     * Derive the public key with ext-sodium.
     *
     * @return null|string Null when the algorithm is not a Curve25519 one or ext-sodium is not available
     */
    public static function viaSodium(AlgorithmIdentifierType $algo, string $privateKey): ?string
    {
        // both Curve25519 private keys are 32 bytes, and ext-sodium throws on anything else
        if (strlen($privateKey) !== 32) {
            return null;
        }
        $oid = $algo->oid();
        if ($oid === AlgorithmIdentifier::OID_ED25519 && function_exists('sodium_crypto_sign_seed_keypair')) {
            return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($privateKey));
        }
        if ($oid === AlgorithmIdentifier::OID_X25519 && function_exists('sodium_crypto_scalarmult_base')) {
            return sodium_crypto_scalarmult_base($privateKey);
        }
        return null;
    }

    /**
     * Derive the public key with the OpenSSL extension.
     *
     * @return null|string Null when the OpenSSL extension cannot derive a public key of this algorithm
     */
    public static function viaOpenSSL(AlgorithmIdentifierType $algo, string $privateKey): ?string
    {
        if (! self::opensslSupports($algo)) {
            return null;
        }
        return self::opensslDerive($algo, $privateKey);
    }

    /**
     * Whether this runtime's OpenSSL extension derives public keys of the given algorithm.
     *
     * Answered once per algorithm by deriving a known test vector. Support depends on both the PHP version and the
     * OpenSSL library it is built against, and an extension that does not know the key type may well return
     * something other than the right key rather than fail, so the result is compared rather than trusted.
     */
    public static function opensslSupports(AlgorithmIdentifierType $algo): bool
    {
        $oid = $algo->oid();
        if (! array_key_exists($oid, self::$opensslSupport)) {
            self::$opensslSupport[$oid] = array_key_exists($oid, self::PROBE_VECTORS)
                && function_exists('openssl_pkey_get_private')
                && self::opensslDerive($algo, (string) hex2bin(self::PROBE_VECTORS[$oid]['private']))
                    === hex2bin(self::PROBE_VECTORS[$oid]['public']);
        }
        return self::$opensslSupport[$oid];
    }

    /**
     * Load the private key into OpenSSL as a minimal PKCS #8 structure and read the public key back.
     */
    private static function opensslDerive(AlgorithmIdentifierType $algo, string $privateKey): ?string
    {
        $der = Sequence::create(
            Integer::create(0),
            $algo->toASN1(),
            OctetString::create(OctetString::create($privateKey)->toDER())
        )->toDER();
        $key = @openssl_pkey_get_private(PEM::create(PEM::TYPE_PRIVATE_KEY, $der)->string());
        $details = $key === false ? false : openssl_pkey_get_details($key);
        // PHP < 8.3 reports these keys as EC and leaves a "param of incompatible type" error behind
        while (openssl_error_string() !== false) {
        }
        $pem = $details === false ? null : $details['key'] ?? null;
        if (! is_string($pem)) {
            return null;
        }
        return PublicKeyInfo::fromPEM(PEM::fromString($pem))
            ->publicKeyData()
            ->string();
    }
}
