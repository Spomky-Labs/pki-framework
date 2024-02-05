<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;

/**
 * @internal
 */
final class AttCertValidityPeriodTest extends TestCase
{
    private static ?DateTimeImmutable $_nb = null;

    private static DateTimeImmutable $_na;

    public static function setUpBeforeClass(): void
    {
        self::$_nb = new DateTimeImmutable('2016-05-17 12:00:00');
        self::$_na = new DateTimeImmutable('2016-05-17 13:00:00');
    }

    public static function tearDownAfterClass(): void
    {
        self::$_nb = null;
    }

    #[Test]
    public function create(): AttCertValidityPeriod
    {
        $validity = AttCertValidityPeriod::create(self::$_nb, self::$_na);
        static::assertInstanceOf(AttCertValidityPeriod::class, $validity);
        return $validity;
    }

    #[Test]
    #[Depends('create')]
    public function encode(AttCertValidityPeriod $validity): string
    {
        $seq = $validity->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): AttCertValidityPeriod
    {
        $iss_ser = AttCertValidityPeriod::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(AttCertValidityPeriod::class, $iss_ser);
        return $iss_ser;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(AttCertValidityPeriod $ref, AttCertValidityPeriod $new)
    {
        static::assertSame($ref->notBeforeTime()->getTimestamp(), $new->notBeforeTime()->getTimestamp());
        static::assertSame($ref->notAfterTime()->getTimestamp(), $new->notAfterTime()->getTimestamp());
    }

    #[Test]
    #[Depends('create')]
    public function notBefore(AttCertValidityPeriod $validity)
    {
        static::assertEquals(self::$_nb, $validity->notBeforeTime());
    }

    #[Test]
    #[Depends('create')]
    public function notAfter(AttCertValidityPeriod $validity)
    {
        static::assertEquals(self::$_na, $validity->notAfterTime());
    }

    #[Test]
    public function fromStrings()
    {
        $validity = AttCertValidityPeriod::fromStrings('now', 'now + 1 day', 'UTC');
        static::assertInstanceOf(AttCertValidityPeriod::class, $validity);
    }
}
