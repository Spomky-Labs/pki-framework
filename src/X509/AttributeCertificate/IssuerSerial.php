<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\AttributeCertificate;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use function strval;

/**
 * Implements *IssuerSerial* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 */
final class IssuerSerial
{
    /**
     * Serial number as a base 10 integer.
     */
    private readonly string $_serial;

    /**
     * @param int|string $serial
     */
    public function __construct(
        /**
         * Issuer name.
         */
        protected GeneralNames $_issuer,
        $serial, /**
     * Issuer unique ID.
     */
        protected ?UniqueIdentifier $_issuerUID = null
    ) {
        $this->_serial = strval($serial);
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $issuer = GeneralNames::fromASN1($seq->at(0)->asSequence());
        $serial = $seq->at(1)
            ->asInteger()
            ->number();
        $uid = null;
        if ($seq->has(2, Element::TYPE_BIT_STRING)) {
            $uid = UniqueIdentifier::fromASN1($seq->at(2)->asBitString());
        }
        return new self($issuer, $serial, $uid);
    }

    /**
     * Initialize from a public key certificate.
     */
    public static function fromPKC(Certificate $cert): self
    {
        $tbsCert = $cert->tbsCertificate();
        $issuer = GeneralNames::create(DirectoryName::create($tbsCert->issuer()));
        $serial = $tbsCert->serialNumber();
        $uid = $tbsCert->hasIssuerUniqueID() ? $tbsCert->issuerUniqueID() : null;
        return new self($issuer, $serial, $uid);
    }

    /**
     * Get issuer name.
     */
    public function issuer(): GeneralNames
    {
        return $this->_issuer;
    }

    /**
     * Get serial number.
     */
    public function serial(): string
    {
        return $this->_serial;
    }

    /**
     * Check whether issuer unique identifier is present.
     */
    public function hasIssuerUID(): bool
    {
        return isset($this->_issuerUID);
    }

    /**
     * Get issuer unique identifier.
     */
    public function issuerUID(): UniqueIdentifier
    {
        if (! $this->hasIssuerUID()) {
            throw new LogicException('issuerUID not set.');
        }
        return $this->_issuerUID;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [$this->_issuer->toASN1(), Integer::create($this->_serial)];
        if (isset($this->_issuerUID)) {
            $elements[] = $this->_issuerUID->toASN1();
        }
        return Sequence::create(...$elements);
    }

    /**
     * Check whether this IssuerSerial identifies given certificate.
     */
    public function identifiesPKC(Certificate $cert): bool
    {
        $tbs = $cert->tbsCertificate();
        if (! $tbs->issuer()->equals($this->_issuer->firstDN())) {
            return false;
        }
        if ($tbs->serialNumber() !== $this->_serial) {
            return false;
        }
        if ($this->_issuerUID !== null && ! $this->_checkUniqueID($cert)) {
            return false;
        }
        return true;
    }

    /**
     * Check whether issuerUID matches given certificate.
     */
    private function _checkUniqueID(Certificate $cert): bool
    {
        if (! $cert->tbsCertificate()->hasIssuerUniqueID()) {
            return false;
        }
        $uid = $cert->tbsCertificate()
            ->issuerUniqueID()
            ->string();
        return $this->_issuerUID?->string() === $uid;
    }
}
