<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\AttributeCertificate;

use DateTimeImmutable;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;
use SpomkyLabs\Pki\X509\Feature\DateTimeHelper;

/**
 * Implements *AttCertValidityPeriod* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 */
final class AttCertValidityPeriod
{
    use DateTimeHelper;

    public function __construct(
        /**
         * Not before time.
         */
        protected DateTimeImmutable $_notBeforeTime,
        /**
         * Not after time.
         */
        protected DateTimeImmutable $_notAfterTime
    ) {
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $nb = $seq->at(0)
            ->asGeneralizedTime()
            ->dateTime();
        $na = $seq->at(1)
            ->asGeneralizedTime()
            ->dateTime();
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
        $nb = self::_createDateTime($nb_date, $tz);
        $na = self::_createDateTime($na_date, $tz);
        return new self($nb, $na);
    }

    /**
     * Get not before time.
     */
    public function notBeforeTime(): DateTimeImmutable
    {
        return $this->_notBeforeTime;
    }

    /**
     * Get not after time.
     */
    public function notAfterTime(): DateTimeImmutable
    {
        return $this->_notAfterTime;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return Sequence::create(new GeneralizedTime($this->_notBeforeTime), new GeneralizedTime($this->_notAfterTime));
    }
}
