<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC;

use LogicException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use UnexpectedValueException;

/**
 * Implements elliptic curve private key type as specified by RFC 5915.
 *
 * @see https://tools.ietf.org/html/rfc5915#section-3
 */
final class ECPrivateKey extends PrivateKey
{
    /**
     * Constructor.
     *
     * @param string $_privateKey Private key
     * @param null|string $_namedCurve OID of the named curve
     * @param null|string $_publicKey ECPoint value
     */
    public function __construct(
        protected string $_privateKey,
        protected ?string $_namedCurve = null,
        protected ?string $_publicKey = null
    ) {
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $version = $seq->at(0)
            ->asInteger()
            ->intNumber();
        if ($version !== 1) {
            throw new UnexpectedValueException('Version must be 1.');
        }
        $private_key = $seq->at(1)
            ->asOctetString()
            ->string();
        $named_curve = null;
        if ($seq->hasTagged(0)) {
            $params = $seq->getTagged(0)
                ->asExplicit();
            $named_curve = $params->asObjectIdentifier()
                ->oid();
        }
        $public_key = null;
        if ($seq->hasTagged(1)) {
            $public_key = $seq->getTagged(1)
                ->asExplicit()
                ->asBitString()
                ->string();
        }
        return new self($private_key, $named_curve, $public_key);
    }

    /**
     * Initialize from DER data.
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
    }

    /**
     * @see PrivateKey::fromPEM()
     */
    public static function fromPEM(PEM $pem): self
    {
        $pk = parent::fromPEM($pem);
        if (! ($pk instanceof self)) {
            throw new UnexpectedValueException('Not an EC private key.');
        }
        return $pk;
    }

    /**
     * Get the EC private key value.
     *
     * @return string Octets of the private key
     */
    public function privateKeyOctets(): string
    {
        return $this->_privateKey;
    }

    /**
     * Whether named curve is present.
     */
    public function hasNamedCurve(): bool
    {
        return isset($this->_namedCurve);
    }

    /**
     * Get named curve OID.
     */
    public function namedCurve(): string
    {
        if (! $this->hasNamedCurve()) {
            throw new LogicException('namedCurve not set.');
        }
        return $this->_namedCurve;
    }

    /**
     * Get self with named curve.
     *
     * @param null|string $named_curve Named curve OID
     */
    public function withNamedCurve(?string $named_curve): self
    {
        $obj = clone $this;
        $obj->_namedCurve = $named_curve;
        return $obj;
    }

    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return new ECPublicKeyAlgorithmIdentifier($this->namedCurve());
    }

    /**
     * Whether public key is present.
     */
    public function hasPublicKey(): bool
    {
        return isset($this->_publicKey);
    }

    /**
     * @return ECPublicKey
     */
    public function publicKey(): PublicKey
    {
        if (! $this->hasPublicKey()) {
            throw new LogicException('publicKey not set.');
        }
        return new ECPublicKey($this->_publicKey, $this->namedCurve());
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [new Integer(1), new OctetString($this->_privateKey)];
        if (isset($this->_namedCurve)) {
            $elements[] = new ExplicitlyTaggedType(0, new ObjectIdentifier($this->_namedCurve));
        }
        if (isset($this->_publicKey)) {
            $elements[] = new ExplicitlyTaggedType(1, new BitString($this->_publicKey));
        }
        return new Sequence(...$elements);
    }

    public function toDER(): string
    {
        return $this->toASN1()
            ->toDER();
    }

    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_EC_PRIVATE_KEY, $this->toDER());
    }
}
