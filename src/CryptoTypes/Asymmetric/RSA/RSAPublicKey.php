<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA;

use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use function strval;
use UnexpectedValueException;

/**
 * Implements PKCS #1 RSAPublicKey ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc2437#section-11.1.1
 */
final class RSAPublicKey extends PublicKey
{
    /**
     * Modulus as a base 10 integer.
     */
    protected string $_modulus;

    /**
     * Public exponent as a base 10 integer.
     */
    protected string $_publicExponent;

    /**
     * Constructor.
     *
     * @param int|string $n Modulus
     * @param int|string $e Public exponent
     */
    public function __construct($n, $e)
    {
        $this->_modulus = strval($n);
        $this->_publicExponent = strval($e);
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $n = $seq->at(0)
            ->asInteger()
            ->number();
        $e = $seq->at(1)
            ->asInteger()
            ->number();
        return new self($n, $e);
    }

    /**
     * Initialize from DER data.
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
    }

    /**
     * @see PublicKey::fromPEM()
     */
    public static function fromPEM(PEM $pem): self
    {
        switch ($pem->type()) {
            case PEM::TYPE_RSA_PUBLIC_KEY:
                return self::fromDER($pem->data());
            case PEM::TYPE_PUBLIC_KEY:
                $pki = PublicKeyInfo::fromDER($pem->data());
                if ($pki->algorithmIdentifier()
                    ->oid() !==
                    AlgorithmIdentifier::OID_RSA_ENCRYPTION) {
                    throw new UnexpectedValueException('Not an RSA public key.');
                }
                return self::fromDER($pki->publicKeyData()->string());
        }
        throw new UnexpectedValueException('Invalid PEM type ' . $pem->type());
    }

    /**
     * Get modulus.
     *
     * @return string Base 10 integer
     */
    public function modulus(): string
    {
        return $this->_modulus;
    }

    /**
     * Get public exponent.
     *
     * @return string Base 10 integer
     */
    public function publicExponent(): string
    {
        return $this->_publicExponent;
    }

    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return new RSAEncryptionAlgorithmIdentifier();
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return new Sequence(new Integer($this->_modulus), new Integer($this->_publicExponent));
    }

    public function toDER(): string
    {
        return $this->toASN1()
            ->toDER();
    }

    /**
     * Generate PEM.
     */
    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_RSA_PUBLIC_KEY, $this->toDER());
    }
}
