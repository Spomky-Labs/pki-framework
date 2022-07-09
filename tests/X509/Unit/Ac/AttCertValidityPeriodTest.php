<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;

/**
 * @internal
 */
final class AttCertValidityPeriodTest extends TestCase
{
    private static $_nb;

    private static $_na;

    public static function setUpBeforeClass(): void
    {
        self::$_nb = new DateTimeImmutable('2016-05-17 12:00:00');
        self::$_na = new DateTimeImmutable('2016-05-17 13:00:00');
    }

    public static function tearDownAfterClass(): void
    {
        self::$_nb = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $validity = new AttCertValidityPeriod(self::$_nb, self::$_na);
        static::assertInstanceOf(AttCertValidityPeriod::class, $validity);
        return $validity;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(AttCertValidityPeriod $validity)
    {
        $seq = $validity->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $iss_ser = AttCertValidityPeriod::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(AttCertValidityPeriod::class, $iss_ser);
        return $iss_ser;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(AttCertValidityPeriod $ref, AttCertValidityPeriod $new)
    {
        static::assertEquals($ref->notBeforeTime() ->getTimestamp(), $new->notBeforeTime() ->getTimestamp());
        static::assertEquals($ref->notAfterTime() ->getTimestamp(), $new->notAfterTime() ->getTimestamp());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function notBefore(AttCertValidityPeriod $validity)
    {
        static::assertEquals(self::$_nb, $validity->notBeforeTime());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function notAfter(AttCertValidityPeriod $validity)
    {
        static::assertEquals(self::$_na, $validity->notAfterTime());
    }

    /**
     * @test
     */
    public function fromStrings()
    {
        $validity = AttCertValidityPeriod::fromStrings('now', 'now + 1 day', 'UTC');
        static::assertInstanceOf(AttCertValidityPeriod::class, $validity);
    }
}
