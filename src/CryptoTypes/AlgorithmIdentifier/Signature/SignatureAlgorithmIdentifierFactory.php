<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature;

use function array_key_exists;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierFactory;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AsymmetricCryptoAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * Factory class for constructing signature algorithm identifiers.
 */
abstract class SignatureAlgorithmIdentifierFactory
{
    /**
     * Mapping of hash algorithm OID's to RSA signature algorithm OID's.
     *
     * @internal
     *
     * @var array<string, string>
     */
    private const MAP_RSA_OID = [
        AlgorithmIdentifier::OID_MD5 => AlgorithmIdentifier::OID_MD5_WITH_RSA_ENCRYPTION,
        AlgorithmIdentifier::OID_SHA1 => AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION,
        AlgorithmIdentifier::OID_SHA224 => AlgorithmIdentifier::OID_SHA224_WITH_RSA_ENCRYPTION,
        AlgorithmIdentifier::OID_SHA256 => AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION,
        AlgorithmIdentifier::OID_SHA384 => AlgorithmIdentifier::OID_SHA384_WITH_RSA_ENCRYPTION,
        AlgorithmIdentifier::OID_SHA512 => AlgorithmIdentifier::OID_SHA512_WITH_RSA_ENCRYPTION,
    ];

    /**
     * Mapping of hash algorithm OID's to EC signature algorithm OID's.
     *
     * @internal
     *
     * @var array<string, string>
     */
    private const MAP_EC_OID = [
        AlgorithmIdentifier::OID_SHA1 => AlgorithmIdentifier::OID_ECDSA_WITH_SHA1,
        AlgorithmIdentifier::OID_SHA224 => AlgorithmIdentifier::OID_ECDSA_WITH_SHA224,
        AlgorithmIdentifier::OID_SHA256 => AlgorithmIdentifier::OID_ECDSA_WITH_SHA256,
        AlgorithmIdentifier::OID_SHA384 => AlgorithmIdentifier::OID_ECDSA_WITH_SHA384,
        AlgorithmIdentifier::OID_SHA512 => AlgorithmIdentifier::OID_ECDSA_WITH_SHA512,
    ];

    /**
     * Get signature algorithm identifier of given asymmetric cryptographic type utilizing given hash algorithm.
     *
     * @param AsymmetricCryptoAlgorithmIdentifier $crypto_algo Cryptographic algorithm identifier, eg. RSA or EC
     * @param HashAlgorithmIdentifier $hash_algo Hash algorithm identifier
     */
    public static function algoForAsymmetricCrypto(
        AsymmetricCryptoAlgorithmIdentifier $crypto_algo,
        HashAlgorithmIdentifier $hash_algo
    ): SignatureAlgorithmIdentifier {
        $oid = match ($crypto_algo->oid()) {
            AlgorithmIdentifier::OID_RSA_ENCRYPTION => self::_oidForRSA($hash_algo),
            AlgorithmIdentifier::OID_EC_PUBLIC_KEY => self::_oidForEC($hash_algo),
            default => throw new UnexpectedValueException(
                sprintf('Crypto algorithm %s not supported.', $crypto_algo->name())
            ),
        };
        $cls = (new AlgorithmIdentifierFactory())->getClass($oid);

        return $cls::create();
    }

    /**
     * Get RSA signature algorithm OID for the given hash algorithm identifier.
     */
    private static function _oidForRSA(HashAlgorithmIdentifier $hash_algo): string
    {
        if (! array_key_exists($hash_algo->oid(), self::MAP_RSA_OID)) {
            throw new UnexpectedValueException(sprintf('No RSA signature algorithm for %s.', $hash_algo->name()));
        }
        return self::MAP_RSA_OID[$hash_algo->oid()];
    }

    /**
     * Get EC signature algorithm OID for the given hash algorithm identifier.
     */
    private static function _oidForEC(HashAlgorithmIdentifier $hash_algo): string
    {
        if (! array_key_exists($hash_algo->oid(), self::MAP_EC_OID)) {
            throw new UnexpectedValueException(sprintf('No EC signature algorithm for %s.', $hash_algo->name()));
        }
        return self::MAP_EC_OID[$hash_algo->oid()];
    }
}
