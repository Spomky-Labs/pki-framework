<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410;

use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Attribute\OneAsymmetricKeyAttributes;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;

/**
 * Implements an intermediary object to store a private key using Curve25519 or Curve448 as defined by RFC 8410.
 *
 * Private keys described in RFC 8410 may only be encoded as `OneAsymmetricKey` and thus version and attributes are also
 * stored in this type.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
abstract class RFC8410PrivateKey extends PrivateKey
{
    /**
     * Version for OneAsymmetricKey.
     *
     * @var int
     */
    protected $_version;

    /**
     * Attributes from OneAsymmetricKey.
     *
     * @var null|OneAsymmetricKeyAttributes
     */
    protected $_attributes;

    /**
     * @param string $_privateKeyData Private key data
     * @param null|string $_publicKeyData Public key data
     */
    public function __construct(
        protected string $_privateKeyData,
        protected ?string $_publicKeyData = null
    ) {
        $this->_version = OneAsymmetricKey::VERSION_2;
        $this->_attributes = null;
    }

    /**
     * Initialize from `CurvePrivateKey` OctetString.
     *
     * @param OctetString $str Private key data wrapped into OctetString
     * @param null|string $public_key Optional public key data
     */
    public static function fromOctetString(OctetString $str, ?string $public_key = null): self
    {
        return new static($str->string(), $public_key);
    }

    /**
     * Get self with version number.
     */
    public function withVersion(int $version): self
    {
        $obj = clone $this;
        $obj->_version = $version;
        return $obj;
    }

    /**
     * Get self with attributes.
     */
    public function withAttributes(?OneAsymmetricKeyAttributes $attribs): self
    {
        $obj = clone $this;
        $obj->_attributes = $attribs;
        return $obj;
    }

    public function privateKeyData(): string
    {
        return $this->_privateKeyData;
    }

    /**
     * Whether public key is set.
     */
    public function hasPublicKey(): bool
    {
        return isset($this->_publicKeyData);
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): OctetString
    {
        return new OctetString($this->_privateKeyData);
    }

    public function toDER(): string
    {
        return $this->toASN1()
            ->toDER();
    }

    public function toPEM(): PEM
    {
        $pub = $this->_publicKeyData ?
            new BitString($this->_publicKeyData) : null;
        $pki = new OneAsymmetricKey($this->algorithmIdentifier(), $this->toDER(), $this->_attributes, $pub);
        return $pki->withVersion($this->_version)
            ->toPEM();
    }
}
