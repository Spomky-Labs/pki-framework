<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate;

use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;

/**
 * Implements *Validity* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1.2.5
 */
final class Validity
{
    public function __construct(
        /**
         * Not before time.
         */
        protected Time $_notBefore,
        /**
         * Not after time.
         */
        protected Time $_notAfter
    ) {
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $nb = Time::fromASN1($seq->at(0)->asTime());
        $na = Time::fromASN1($seq->at(1)->asTime());
        return new self($nb, $na);
    }

    /**
     * Initialize from date strings.
     *
     * @param null|string $nb_date Not before date
     * @param null|string $na_date Not after date
     * @param null|string $tz Timezone string
     */
    public static function fromStrings(?string $nb_date, ?string $na_date, ?string $tz = null): self
    {
        return new self(Time::fromString($nb_date, $tz), Time::fromString($na_date, $tz));
    }

    /**
     * Get not before time.
     */
    public function notBefore(): Time
    {
        return $this->_notBefore;
    }

    /**
     * Get not after time.
     */
    public function notAfter(): Time
    {
        return $this->_notAfter;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return Sequence::create($this->_notBefore->toASN1(), $this->_notAfter->toASN1());
    }
}
