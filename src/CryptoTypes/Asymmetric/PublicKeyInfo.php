<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric;

use function chr;
use function ord;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\Ed25519PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\X25519PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\Ed448PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\X448PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use UnexpectedValueException;

/**
 * Implements X.509 SubjectPublicKeyInfo ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1
 */
final class PublicKeyInfo
{
    /**
     * @param AlgorithmIdentifierType $_algo Algorithm
     * @param BitString $_publicKey Public key data
     */
    public function __construct(
        protected AlgorithmIdentifierType $_algo,
        protected BitString $_publicKey
    ) {
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $algo = AlgorithmIdentifier::fromASN1($seq->at(0)->asSequence());
        $key = $seq->at(1)
            ->asBitString();
        return new self($algo, $key);
    }

    /**
     * Initialize from a PublicKey.
     */
    public static function fromPublicKey(PublicKey $key): self
    {
        return new self($key->algorithmIdentifier(), $key->subjectPublicKey());
    }

    /**
     * Initialize from PEM.
     */
    public static function fromPEM(PEM $pem): self
    {
        return match ($pem->type()) {
            PEM::TYPE_PUBLIC_KEY => self::fromDER($pem->data()),
            PEM::TYPE_RSA_PUBLIC_KEY => RSAPublicKey::fromDER($pem->data())->publicKeyInfo(),
            default => throw new UnexpectedValueException('Invalid PEM type.'),
        };
    }

    /**
     * Initialize from DER data.
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
    }

    /**
     * Get algorithm identifier.
     */
    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return $this->_algo;
    }

    /**
     * Get public key data.
     */
    public function publicKeyData(): BitString
    {
        return $this->_publicKey;
    }

    /**
     * Get public key.
     */
    public function publicKey(): PublicKey
    {
        $algo = $this->algorithmIdentifier();
        switch ($algo->oid()) {
            // RSA
            case AlgorithmIdentifier::OID_RSA_ENCRYPTION:
                return RSAPublicKey::fromDER($this->_publicKey->string());
            // Elliptic Curve
            case AlgorithmIdentifier::OID_EC_PUBLIC_KEY:
                if (! $algo instanceof ECPublicKeyAlgorithmIdentifier) {
                    throw new UnexpectedValueException('Not an EC algorithm.');
                }
                // ECPoint is directly mapped into public key data
                return new ECPublicKey($this->_publicKey->string(), $algo->namedCurve());
            // Ed25519
            case AlgorithmIdentifier::OID_ED25519:
                return new Ed25519PublicKey($this->_publicKey->string());
            // X25519
            case AlgorithmIdentifier::OID_X25519:
                return new X25519PublicKey($this->_publicKey->string());
            // Ed448
            case AlgorithmIdentifier::OID_ED448:
                return new Ed448PublicKey($this->_publicKey->string());
            // X448
            case AlgorithmIdentifier::OID_X448:
                return new X448PublicKey($this->_publicKey->string());
        }
        throw new RuntimeException('Public key ' . $algo->name() . ' not supported.');
    }

    /**
     * Get key identifier using method 1 as described by RFC 5280.
     *
     * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.2
     *
     * @return string 20 bytes (160 bits) long identifier
     */
    public function keyIdentifier(): string
    {
        return sha1($this->_publicKey->string(), true);
    }

    /**
     * Get key identifier using method 2 as described by RFC 5280.
     *
     * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.2
     *
     * @return string 8 bytes (64 bits) long identifier
     */
    public function keyIdentifier64(): string
    {
        $id = mb_substr($this->keyIdentifier(), -8, null, '8bit');
        $c = (ord($id[0]) & 0x0f) | 0x40;
        $id[0] = chr($c);
        return $id;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return Sequence::create($this->_algo->toASN1(), $this->_publicKey);
    }

    /**
     * Generate DER encoding.
     */
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
        return new PEM(PEM::TYPE_PUBLIC_KEY, $this->toDER());
    }
}
