<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\CertificationRequest;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use UnexpectedValueException;

/**
 * Implements *CertificationRequestInfo* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc2986#section-4
 */
final class CertificationRequestInfo
{
    final public const VERSION_1 = 0;

    /**
     * Version.
     */
    private readonly int $_version;

    /**
     * Attributes.
     *
     * @var null|Attributes
     */
    private $_attributes;

    /**
     * @param Name $_subject Subject
     * @param PublicKeyInfo $_subjectPKInfo Public key info
     */
    public function __construct(
        protected Name $_subject,
        protected PublicKeyInfo $_subjectPKInfo
    ) {
        $this->_version = self::VERSION_1;
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $version = $seq->at(0)
            ->asInteger()
            ->intNumber();
        if ($version !== self::VERSION_1) {
            throw new UnexpectedValueException("Version {$version} not supported.");
        }
        $subject = Name::fromASN1($seq->at(1)->asSequence());
        $pkinfo = PublicKeyInfo::fromASN1($seq->at(2)->asSequence());
        $obj = new self($subject, $pkinfo);
        if ($seq->hasTagged(0)) {
            $obj->_attributes = Attributes::fromASN1($seq->getTagged(0)->asImplicit(Element::TYPE_SET)->asSet());
        }
        return $obj;
    }

    public function version(): int
    {
        return $this->_version;
    }

    /**
     * Get self with subject.
     */
    public function withSubject(Name $subject): self
    {
        $obj = clone $this;
        $obj->_subject = $subject;
        return $obj;
    }

    public function subject(): Name
    {
        return $this->_subject;
    }

    /**
     * Get subject public key info.
     */
    public function subjectPKInfo(): PublicKeyInfo
    {
        return $this->_subjectPKInfo;
    }

    /**
     * Whether certification request info has attributes.
     */
    public function hasAttributes(): bool
    {
        return isset($this->_attributes);
    }

    public function attributes(): Attributes
    {
        if (! $this->hasAttributes()) {
            throw new LogicException('No attributes.');
        }
        return $this->_attributes;
    }

    /**
     * Get instance of self with attributes.
     */
    public function withAttributes(Attributes $attribs): self
    {
        $obj = clone $this;
        $obj->_attributes = $attribs;
        return $obj;
    }

    /**
     * Get self with extension request attribute.
     *
     * @param Extensions $extensions Extensions to request
     */
    public function withExtensionRequest(Extensions $extensions): self
    {
        $obj = clone $this;
        if (! isset($obj->_attributes)) {
            $obj->_attributes = Attributes::create();
        }
        $obj->_attributes = $obj->_attributes->withUnique(
            Attribute::fromAttributeValues(new ExtensionRequestValue($extensions))
        );
        return $obj;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [Integer::create($this->_version), $this->_subject->toASN1(), $this->_subjectPKInfo->toASN1()];
        if (isset($this->_attributes)) {
            $elements[] = ImplicitlyTaggedType::create(0, $this->_attributes->toASN1());
        }
        return Sequence::create(...$elements);
    }

    /**
     * Create signed CertificationRequest.
     *
     * @param SignatureAlgorithmIdentifier $algo Algorithm used for signing
     * @param PrivateKeyInfo $privkey_info Private key used for signing
     * @param null|Crypto $crypto Crypto engine, use default if not set
     */
    public function sign(
        SignatureAlgorithmIdentifier $algo,
        PrivateKeyInfo $privkey_info,
        ?Crypto $crypto = null
    ): CertificationRequest {
        $crypto ??= Crypto::getDefault();
        $data = $this->toASN1()
            ->toDER();
        $signature = $crypto->sign($data, $privkey_info, $algo);
        return new CertificationRequest($this, $algo, $signature);
    }
}
