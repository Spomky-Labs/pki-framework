<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate;

use Brick\Math\BigInteger;
use function count;
use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequest;
use function strval;
use UnexpectedValueException;

/**
 * Implements *TBSCertificate* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1.2
 */
final class TBSCertificate
{
    // Certificate version enumerations
    final public const VERSION_1 = 0;

    final public const VERSION_2 = 1;

    final public const VERSION_3 = 2;

    /**
     * Certificate version.
     */
    private ?int $_version = null;

    /**
     * Serial number.
     */
    private ?string $_serialNumber = null;

    /**
     * Signature algorithm.
     *
     * @var null|SignatureAlgorithmIdentifier
     */
    private $_signature;

    /**
     * Issuer unique identifier.
     */
    private ?UniqueIdentifier $_issuerUniqueID = null;

    /**
     * Subject unique identifier.
     */
    private ?UniqueIdentifier $_subjectUniqueID = null;

    /**
     * Extensions.
     */
    private Extensions $_extensions;

    /**
     * @param Name $_subject Certificate subject
     * @param PublicKeyInfo $_subjectPublicKeyInfo Subject public key
     * @param Name $_issuer Certificate issuer
     * @param Validity $_validity Validity period
     */
    public function __construct(
        protected Name $_subject,
        protected PublicKeyInfo $_subjectPublicKeyInfo,
        protected Name $_issuer,
        protected Validity $_validity
    ) {
        $this->_extensions = new Extensions();
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $idx = 0;
        if ($seq->hasTagged(0)) {
            ++$idx;
            $version = $seq->getTagged(0)
                ->asExplicit()
                ->asInteger()
                ->intNumber();
        } else {
            $version = self::VERSION_1;
        }
        $serial = $seq->at($idx++)
            ->asInteger()
            ->number();
        $algo = AlgorithmIdentifier::fromASN1($seq->at($idx++)->asSequence());
        if (! $algo instanceof SignatureAlgorithmIdentifier) {
            throw new UnexpectedValueException('Unsupported signature algorithm ' . $algo->name() . '.');
        }
        $issuer = Name::fromASN1($seq->at($idx++)->asSequence());
        $validity = Validity::fromASN1($seq->at($idx++)->asSequence());
        $subject = Name::fromASN1($seq->at($idx++)->asSequence());
        $pki = PublicKeyInfo::fromASN1($seq->at($idx++)->asSequence());
        $tbs_cert = new self($subject, $pki, $issuer, $validity);
        $tbs_cert->_version = $version;
        $tbs_cert->_serialNumber = $serial;
        $tbs_cert->_signature = $algo;
        if ($seq->hasTagged(1)) {
            $tbs_cert->_issuerUniqueID = UniqueIdentifier::fromASN1(
                $seq->getTagged(1)
                    ->asImplicit(Element::TYPE_BIT_STRING)
                    ->asBitString()
            );
        }
        if ($seq->hasTagged(2)) {
            $tbs_cert->_subjectUniqueID = UniqueIdentifier::fromASN1(
                $seq->getTagged(2)
                    ->asImplicit(Element::TYPE_BIT_STRING)
                    ->asBitString()
            );
        }
        if ($seq->hasTagged(3)) {
            $tbs_cert->_extensions = Extensions::fromASN1($seq->getTagged(3)->asExplicit()->asSequence());
        }
        return $tbs_cert;
    }

    /**
     * Initialize from certification request.
     *
     * Note that signature is not verified and must be done by the caller.
     */
    public static function fromCSR(CertificationRequest $cr): self
    {
        $cri = $cr->certificationRequestInfo();
        $tbs_cert = new self($cri->subject(), $cri->subjectPKInfo(), new Name(), Validity::fromStrings(null, null));
        // if CSR has Extension Request attribute
        if ($cri->hasAttributes()) {
            $attribs = $cri->attributes();
            if ($attribs->hasExtensionRequest()) {
                $tbs_cert = $tbs_cert->withExtensions($attribs->extensionRequest()->extensions());
            }
        }
        // add Subject Key Identifier extension
        return $tbs_cert->withAdditionalExtensions(
            new SubjectKeyIdentifierExtension(false, $cri->subjectPKInfo()->keyIdentifier())
        );
    }

    /**
     * Get self with fields set from the issuer's certificate.
     *
     * Issuer shall be set to issuing certificate's subject. Authority key identifier extensions shall be added with a
     * key identifier set to issuing certificate's public key identifier.
     *
     * @param Certificate $cert Issuing party's certificate
     */
    public function withIssuerCertificate(Certificate $cert): self
    {
        $obj = clone $this;
        // set issuer DN from cert's subject
        $obj->_issuer = $cert->tbsCertificate()
            ->subject();
        // add authority key identifier extension
        $key_id = $cert->tbsCertificate()
            ->subjectPublicKeyInfo()
            ->keyIdentifier();
        $obj->_extensions = $obj->_extensions->withExtensions(new AuthorityKeyIdentifierExtension(false, $key_id));
        return $obj;
    }

    /**
     * Get self with given version.
     *
     * If version is not set, appropriate version is automatically determined during signing.
     */
    public function withVersion(int $version): self
    {
        $obj = clone $this;
        $obj->_version = $version;
        return $obj;
    }

    /**
     * Get self with given serial number.
     *
     * @param int|string $serial Base 10 number
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
     * Get self with given signature algorithm.
     */
    public function withSignature(SignatureAlgorithmIdentifier $algo): self
    {
        $obj = clone $this;
        $obj->_signature = $algo;
        return $obj;
    }

    /**
     * Get self with given issuer.
     */
    public function withIssuer(Name $issuer): self
    {
        $obj = clone $this;
        $obj->_issuer = $issuer;
        return $obj;
    }

    /**
     * Get self with given validity.
     */
    public function withValidity(Validity $validity): self
    {
        $obj = clone $this;
        $obj->_validity = $validity;
        return $obj;
    }

    /**
     * Get self with given subject.
     */
    public function withSubject(Name $subject): self
    {
        $obj = clone $this;
        $obj->_subject = $subject;
        return $obj;
    }

    /**
     * Get self with given subject public key info.
     */
    public function withSubjectPublicKeyInfo(PublicKeyInfo $pub_key_info): self
    {
        $obj = clone $this;
        $obj->_subjectPublicKeyInfo = $pub_key_info;
        return $obj;
    }

    /**
     * Get self with issuer unique ID.
     */
    public function withIssuerUniqueID(UniqueIdentifier $id): self
    {
        $obj = clone $this;
        $obj->_issuerUniqueID = $id;
        return $obj;
    }

    /**
     * Get self with subject unique ID.
     */
    public function withSubjectUniqueID(UniqueIdentifier $id): self
    {
        $obj = clone $this;
        $obj->_subjectUniqueID = $id;
        return $obj;
    }

    /**
     * Get self with given extensions.
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

    /**
     * Check whether version is set.
     */
    public function hasVersion(): bool
    {
        return isset($this->_version);
    }

    /**
     * Get certificate version.
     */
    public function version(): int
    {
        if (! $this->hasVersion()) {
            throw new LogicException('version not set.');
        }
        return $this->_version;
    }

    /**
     * Check whether serial number is set.
     */
    public function hasSerialNumber(): bool
    {
        return isset($this->_serialNumber);
    }

    /**
     * Get serial number.
     *
     * @return string Base 10 integer
     */
    public function serialNumber(): string
    {
        if (! $this->hasSerialNumber()) {
            throw new LogicException('serialNumber not set.');
        }
        return $this->_serialNumber;
    }

    /**
     * Check whether signature algorithm is set.
     */
    public function hasSignature(): bool
    {
        return isset($this->_signature);
    }

    /**
     * Get signature algorithm.
     */
    public function signature(): SignatureAlgorithmIdentifier
    {
        if (! $this->hasSignature()) {
            throw new LogicException('signature not set.');
        }
        return $this->_signature;
    }

    public function issuer(): Name
    {
        return $this->_issuer;
    }

    /**
     * Get validity period.
     */
    public function validity(): Validity
    {
        return $this->_validity;
    }

    public function subject(): Name
    {
        return $this->_subject;
    }

    /**
     * Get subject public key.
     */
    public function subjectPublicKeyInfo(): PublicKeyInfo
    {
        return $this->_subjectPublicKeyInfo;
    }

    /**
     * Whether issuer unique identifier is present.
     */
    public function hasIssuerUniqueID(): bool
    {
        return isset($this->_issuerUniqueID);
    }

    public function issuerUniqueID(): UniqueIdentifier
    {
        if (! $this->hasIssuerUniqueID()) {
            throw new LogicException('issuerUniqueID not set.');
        }
        return $this->_issuerUniqueID;
    }

    /**
     * Whether subject unique identifier is present.
     */
    public function hasSubjectUniqueID(): bool
    {
        return isset($this->_subjectUniqueID);
    }

    public function subjectUniqueID(): UniqueIdentifier
    {
        if (! $this->hasSubjectUniqueID()) {
            throw new LogicException('subjectUniqueID not set.');
        }
        return $this->_subjectUniqueID;
    }

    public function extensions(): Extensions
    {
        return $this->_extensions;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [];
        $version = $this->version();
        // if version is not default
        if ($version !== self::VERSION_1) {
            $elements[] = new ExplicitlyTaggedType(0, new Integer($version));
        }
        $serial = $this->serialNumber();
        $signature = $this->signature();
        // add required elements
        array_push(
            $elements,
            new Integer($serial),
            $signature->toASN1(),
            $this->_issuer->toASN1(),
            $this->_validity->toASN1(),
            $this->_subject->toASN1(),
            $this->_subjectPublicKeyInfo->toASN1()
        );
        if (isset($this->_issuerUniqueID)) {
            $elements[] = new ImplicitlyTaggedType(1, $this->_issuerUniqueID->toASN1());
        }
        if (isset($this->_subjectUniqueID)) {
            $elements[] = new ImplicitlyTaggedType(2, $this->_subjectUniqueID->toASN1());
        }
        if (count($this->_extensions)) {
            $elements[] = new ExplicitlyTaggedType(3, $this->_extensions->toASN1());
        }
        return Sequence::create(...$elements);
    }

    /**
     * Create signed certificate.
     *
     * @param SignatureAlgorithmIdentifier $algo Algorithm used for signing
     * @param PrivateKeyInfo $privkey_info Private key used for signing
     * @param null|Crypto $crypto Crypto engine, use default if not set
     */
    public function sign(
        SignatureAlgorithmIdentifier $algo,
        PrivateKeyInfo $privkey_info,
        ?Crypto $crypto = null
    ): Certificate {
        $crypto ??= Crypto::getDefault();
        $tbs_cert = clone $this;
        if (! isset($tbs_cert->_version)) {
            $tbs_cert->_version = $tbs_cert->_determineVersion();
        }
        if (! isset($tbs_cert->_serialNumber)) {
            $tbs_cert->_serialNumber = strval(0);
        }
        $tbs_cert->_signature = $algo;
        $data = $tbs_cert->toASN1()
            ->toDER();
        $signature = $crypto->sign($data, $privkey_info, $algo);
        return new Certificate($tbs_cert, $algo, $signature);
    }

    /**
     * Determine minimum version for the certificate.
     */
    private function _determineVersion(): int
    {
        // if extensions are present
        if (count($this->_extensions)) {
            return self::VERSION_3;
        }
        // if UniqueIdentifier is present
        if (isset($this->_issuerUniqueID) || isset($this->_subjectUniqueID)) {
            return self::VERSION_2;
        }
        return self::VERSION_1;
    }
}
