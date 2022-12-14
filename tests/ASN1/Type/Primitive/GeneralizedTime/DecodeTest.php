<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\GeneralizedTime;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @test
     */
    public function type()
    {
        $el = GeneralizedTime::fromDER("\x18\x15" . '20060102220405.99999Z');
        static::assertInstanceOf(GeneralizedTime::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $date = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $el = GeneralizedTime::fromDER("\x18\x0f" . '20060102220405Z');
        static::assertEquals($date, $el->dateTime()->getTimestamp());
    }

    /**
     * @test
     */
    public function fractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.99999", new DateTimeZone('UTC'));
        $el = GeneralizedTime::fromDER("\x18\x15" . '20060102220405.99999Z');
        static::assertEquals($dt->format('c u'), $el->dateTime()->format('c u'));
    }

    /**
     * @test
     */
    public function noFractions()
    {
        $dt = new DateTimeImmutable('Mon Jan 2 15:04:05 MST 2006');
        $dt = $dt->setTimezone(new DateTimeZone('UTC'));
        $el = GeneralizedTime::fromDER("\x18\x0f" . '20060102220405Z');
        static::assertEquals($dt->format('c u'), $el->dateTime()->format('c u'));
    }

    /**
     * @test
     */
    public function invalidFractions()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('omit trailing zeroes');
        GeneralizedTime::fromDER("\x18\x12" . '20060102220405.50Z');
    }

    /**
     * @test
     */
    public function invalidFractions2()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('omit trailing zeroes');
        GeneralizedTime::fromDER("\x18\x11" . '20060102220405.0Z');
    }

    /**
     * @test
     */
    public function invalidFractionsOnlyDot()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid GeneralizedTime format');
        GeneralizedTime::fromDER("\x18\x10" . '20060102220405.Z');
    }

    /**
     * @test
     */
    public function noTimezone()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid GeneralizedTime format');
        GeneralizedTime::fromDER("\x18\x0e" . '20060102220405');
    }

    /**
     * @test
     */
    public function invalidTime()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Failed to decode GeneralizedTime');
        GeneralizedTime::fromDER("\x18\x19" . '20060102220405.123456789Z');
    }
}
