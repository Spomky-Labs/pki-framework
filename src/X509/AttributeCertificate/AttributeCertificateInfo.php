<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\AttributeCertificate;

use Brick\Math\BigInteger;
use function count;
use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;
use function strval;
use UnexpectedValueException;

/**
 * Implements *AttributeCertificateInfo* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 */
final class AttributeCertificateInfo
{
    final public const VERSION_2 = 1;

    /**
     * AC version.
     */
    private readonly int $_version;

    /**
     * Signature algorithm identifier.
     *
     * @var SignatureAlgorithmIdentifier
     */
    private $_signature;

    /**
     * AC serial number as a base 10 integer.
     */
    private ?string $_serialNumber = null;

    /**
     * Issuer unique identifier.
     */
    private ?UniqueIdentifier $_issuerUniqueID = null;

    /**
     * Extensions.
     */
    private Extensions $_extensions;

    /**
     * @param Holder $_holder AC holder
     * @param AttCertIssuer $_issuer AC issuer
     * @param AttCertValidityPeriod $_attrCertValidityPeriod Validity
     * @param Attributes $_attributes Attributes
     */
    public function __construct(
        protected Holder $_holder,
        protected AttCertIssuer $_issuer,
        protected AttCertValidityPeriod $_attrCertValidityPeriod,
        protected Attributes $_attributes
    ) {
        $this->_version = self::VERSION_2;
        $this->_extensions = new Extensions();
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $idx = 0;
        $version = $seq->at($idx++)
            ->asInteger()
            ->intNumber();
        if ($version !== self::VERSION_2) {
            throw new UnexpectedValueException('Version must be 2.');
        }
        $holder = Holder::fromASN1($seq->at($idx++)->asSequence());
        $issuer = AttCertIssuer::fromASN1($seq->at($idx++));
        $signature = AlgorithmIdentifier::fromASN1($seq->at($idx++)->asSequence());
        if (! $signature instanceof SignatureAlgorithmIdentifier) {
            throw new UnexpectedValueException('Unsupported signature algorithm ' . $signature->oid() . '.');
        }
        $serial = $seq->at($idx++)
            ->asInteger()
            ->number();
        $validity = AttCertValidityPeriod::fromASN1($seq->at($idx++)->asSequence());
        $attribs = Attributes::fromASN1($seq->at($idx++)->asSequence());
        $obj = new self($holder, $issuer, $validity, $attribs);
        $obj->_signature = $signature;
        $obj->_serialNumber = $serial;
        if ($seq->has($idx, Element::TYPE_BIT_STRING)) {
            $obj->_issuerUniqueID = UniqueIdentifier::fromASN1($seq->at($idx++)->asBitString());
        }
        if ($seq->has($idx, Element::TYPE_SEQUENCE)) {
            $obj->_extensions = Extensions::fromASN1($seq->at($idx++)->asSequence());
        }
        return $obj;
    }

    /**
     * Get self with holder.
     */
    public function withHolder(Holder $holder): self
    {
        $obj = clone $this;
        $obj->_holder = $holder;
        return $obj;
    }

    /**
     * Get self with issuer.
     */
    public function withIssuer(AttCertIssuer $issuer): self
    {
        $obj = clone $this;
        $obj->_issuer = $issuer;
        return $obj;
    }

    /**
     * Get self with signature algorithm identifier.
     */
    public function withSignature(SignatureAlgorithmIdentifier $algo): self
    {
        $obj = clone $this;
        $obj->_signature = $algo;
        return $obj;
    }

    /**
     * Get self with serial number.
     *
     * @param int|string $serial Base 10 serial number
     */
    public function withSerialNumber(int|string $serial): self
    {
        $obj = clone $this;
        $obj->_serialNumber = strval($serial);
        return $obj;
    }

    /**
     * Get self with random positive serial number.
     *
     * @param int $size Number of random bytes
     */
    public function withRandomSerialNumber(int $size): self
    {
        // ensure that first byte is always non-zero and having first bit unset
        $num = BigInteger::of(random_int(1, 0x7f));
        for ($i = 1; $i < $size; ++$i) {
            $num = $num->shiftedLeft(8);
            $num = $num->plus(random_int(0, 0xff));
        }
        return $this->withSerialNumber($num->toBase(10));
    }

    /**
     * Get self with validity period.
     */
    public function withValidity(AttCertValidityPeriod $validity): self
    {
        $obj = clone $this;
        $obj->_attrCertValidityPeriod = $validity;
        return $obj;
    }

    /**
     * Get self with attributes.
     */
    public function withAttributes(Attributes $attribs): self
    {
        $obj = clone $this;
        $obj->_attributes = $attribs;
        return $obj;
    }

    /**
     * Get self with issuer unique identifier.
     */
    public function withIssuerUniqueID(UniqueIdentifier $uid): self
    {
        $obj = clone $this;
        $obj->_issuerUniqueID = $uid;
        return $obj;
    }

    /**
     * Get self with extensions.
     */
    public function withExtensions(Extensions $extensions): self
    {
        $obj = clone $this;
        $obj->_extensions = $extensions;
        return $obj;
    }

    /**
     * Get self with extensions added.
     *
     * @param Extension ...$exts One or more Extension objects
     */
    public function withAdditionalExtensions(Extension ...$exts): self
    {
        $obj = clone $this;
        $obj->_extensions = $obj->_extensions->withExtensions(...$exts);
        return $obj;
    }

    public function version(): int
    {
        return $this->_version;
    }

    /**
     * Get AC holder.
     */
    public function holder(): Holder
    {
        return $this->_holder;
    }

    /**
     * Get AC issuer.
     */
    public function issuer(): AttCertIssuer
    {
        return $this->_issuer;
    }

    /**
     * Check whether signature is set.
     */
    public function hasSignature(): bool
    {
        return isset($this->_signature);
    }

    /**
     * Get signature algorithm identifier.
     */
    public function signature(): SignatureAlgorithmIdentifier
    {
        if (! $this->hasSignature()) {
            throw new LogicException('signature not set.');
        }
        return $this->_signature;
    }

    /**
     * Check whether serial number is present.
     */
    public function hasSerialNumber(): bool
    {
        return isset($this->_serialNumber);
    }

    /**
     * Get AC serial number as a base 10 integer.
     */
    public function serialNumber(): string
    {
        if (! $this->hasSerialNumber()) {
            throw new LogicException('serialNumber not set.');
        }
        return $this->_serialNumber;
    }

    /**
     * Get validity period.
     */
    public function validityPeriod(): AttCertValidityPeriod
    {
        return $this->_attrCertValidityPeriod;
    }

    public function attributes(): Attributes
    {
        return $this->_attributes;
    }

    /**
     * Check whether issuer unique identifier is present.
     */
    public function hasIssuerUniqueID(): bool
    {
        return isset($this->_issuerUniqueID);
    }

    /**
     * Get issuer unique identifier.
     */
    public function issuerUniqueID(): UniqueIdentifier
    {
        if (! $this->hasIssuerUniqueID()) {
            throw new LogicException('issuerUniqueID not set.');
        }
        return $this->_issuerUniqueID;
    }

    public function extensions(): Extensions
    {
        return $this->_extensions;
    }

    /**
     * Get ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [new Integer($this->_version), $this->_holder->toASN1(),
            $this->_issuer->toASN1(), $this->signature()
                ->toASN1(),
            new Integer($this->serialNumber()),
            $this->_attrCertValidityPeriod->toASN1(),
            $this->_attributes->toASN1(), ];
        if (isset($this->_issuerUniqueID)) {
            $elements[] = $this->_issuerUniqueID->toASN1();
        }
        if (count($this->_extensions) !== 0) {
            $elements[] = $this->_extensions->toASN1();
        }
        return Sequence::create(...$elements);
    }

    /**
     * Create signed attribute certificate.
     *
     * @param SignatureAlgorithmIdentifier $algo Signature algorithm
     * @param PrivateKeyInfo $privkey_info Private key
     * @param null|Crypto $crypto Crypto engine, use default if not set
     */
    public function sign(
        SignatureAlgorithmIdentifier $algo,
        PrivateKeyInfo $privkey_info,
        ?Crypto $crypto = null
    ): AttributeCertificate {
        $crypto ??= Crypto::getDefault();
        $aci = clone $this;
        if (! isset($aci->_serialNumber)) {
            $aci->_serialNumber = '0';
        }
        $aci->_signature = $algo;
        $data = $aci->toASN1()
            ->toDER();
        $signature = $crypto->sign($data, $privkey_info, $algo);
        return new AttributeCertificate($aci, $algo, $signature);
    }
}
