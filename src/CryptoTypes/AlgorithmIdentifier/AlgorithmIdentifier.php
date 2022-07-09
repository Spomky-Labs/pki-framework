<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\AlgorithmIdentifier;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;

/**
 * Implements AlgorithmIdentifier ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc2898#appendix-C
 * @see https://tools.ietf.org/html/rfc3447#appendix-C
 */
abstract class AlgorithmIdentifier implements AlgorithmIdentifierType
{
    // RSA encryption
    final public const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

    // RSA signature algorithms
    final public const OID_MD2_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.2';

    final public const OID_MD4_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.3';

    final public const OID_MD5_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.4';

    final public const OID_SHA1_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.5';

    final public const OID_SHA256_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.11';

    final public const OID_SHA384_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.12';

    final public const OID_SHA512_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.13';

    final public const OID_SHA224_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.14';

    // Elliptic Curve signature algorithms
    final public const OID_ECDSA_WITH_SHA1 = '1.2.840.10045.4.1';

    final public const OID_ECDSA_WITH_SHA224 = '1.2.840.10045.4.3.1';

    final public const OID_ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';

    final public const OID_ECDSA_WITH_SHA384 = '1.2.840.10045.4.3.3';

    final public const OID_ECDSA_WITH_SHA512 = '1.2.840.10045.4.3.4';

    // Elliptic Curve public key
    final public const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

    // Elliptic curve / algorithm pairs from RFC 8410
    final public const OID_X25519 = '1.3.101.110';

    final public const OID_X448 = '1.3.101.111';

    final public const OID_ED25519 = '1.3.101.112';

    final public const OID_ED448 = '1.3.101.113';

    // Cipher algorithms
    final public const OID_DES_CBC = '1.3.14.3.2.7';

    final public const OID_RC2_CBC = '1.2.840.113549.3.2';

    final public const OID_DES_EDE3_CBC = '1.2.840.113549.3.7';

    final public const OID_AES_128_CBC = '2.16.840.1.101.3.4.1.2';

    final public const OID_AES_192_CBC = '2.16.840.1.101.3.4.1.22';

    final public const OID_AES_256_CBC = '2.16.840.1.101.3.4.1.42';

    // HMAC-SHA-1 from RFC 8018
    final public const OID_HMAC_WITH_SHA1 = '1.2.840.113549.2.7';

    // HMAC algorithms from RFC 4231
    final public const OID_HMAC_WITH_SHA224 = '1.2.840.113549.2.8';

    final public const OID_HMAC_WITH_SHA256 = '1.2.840.113549.2.9';

    final public const OID_HMAC_WITH_SHA384 = '1.2.840.113549.2.10';

    final public const OID_HMAC_WITH_SHA512 = '1.2.840.113549.2.11';

    // Message digest algorithms
    final public const OID_MD5 = '1.2.840.113549.2.5';

    final public const OID_SHA1 = '1.3.14.3.2.26';

    final public const OID_SHA224 = '2.16.840.1.101.3.4.2.4';

    final public const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

    final public const OID_SHA384 = '2.16.840.1.101.3.4.2.2';

    final public const OID_SHA512 = '2.16.840.1.101.3.4.2.3';

    /**
     * Object identifier.
     *
     * @var string
     */
    protected $_oid;

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        return (new AlgorithmIdentifierFactory())->parse($seq);
    }

    public function oid(): string
    {
        return $this->_oid;
    }

    public function toASN1(): Sequence
    {
        $elements = [new ObjectIdentifier($this->_oid)];
        $params = $this->_paramsASN1();
        if (isset($params)) {
            $elements[] = $params;
        }
        return new Sequence(...$elements);
    }

    /**
     * Get algorithm identifier parameters as ASN.1.
     *
     * If type allows parameters to be omitted, return null.
     */
    abstract protected function _paramsASN1(): ?Element;
}
