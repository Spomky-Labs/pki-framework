<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410;

use LogicException;
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
     */
    protected int $_version;

    /**
     * Attributes from OneAsymmetricKey.
     */
    protected ?OneAsymmetricKeyAttributes $_attributes;

    /**
     * Public key derived from the private key, when the structure does not embed it.
     *
     * Derived once and carried over by the `with*()` methods, which never change the key itself.
     */
    private ?string $derivedPublicKeyData = null;

    /**
     * @param string $_privateKeyData Private key data
     * @param null|string $_publicKeyData Public key data
     */
    protected function __construct(
        protected string $_privateKeyData,
        protected ?string $_publicKeyData = null
    ) {
        $this->_version = OneAsymmetricKey::VERSION_2;
        $this->_attributes = null;
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
     * Whether the public key is embedded in the structure.
     *
     * `publicKey()` also works when it is not, by deriving the public key from the private key.
     */
    public function hasPublicKey(): bool
    {
        return isset($this->_publicKeyData);
    }

    /**
     * Get the raw public key: the embedded one if there is one, otherwise derived from the private key.
     *
     * @throws LogicException If the public key is not embedded and this runtime cannot derive it
     */
    protected function publicKeyBytes(): string
    {
        if ($this->_publicKeyData !== null) {
            return $this->_publicKeyData;
        }
        return $this->derivedPublicKeyData ??= PublicKeyDerivation::derive(
            $this->algorithmIdentifier(),
            $this->_privateKeyData
        );
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): OctetString
    {
        return OctetString::create($this->_privateKeyData);
    }

    public function toDER(): string
    {
        return $this->toASN1()
            ->toDER();
    }

    public function toPEM(): PEM
    {
        $pub = $this->_publicKeyData === null ? null :
            BitString::create($this->_publicKeyData);

        return OneAsymmetricKey::create($this->algorithmIdentifier(), $this->toDER(), $this->_attributes, $pub)
            ->withVersion($this->_version)
            ->toPEM();
    }
}
