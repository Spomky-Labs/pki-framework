<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Regression;

use function chr;
use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTCTime;

/**
 * @internal
 */
final class UTCTimeCenturyTest extends TestCase
{
    /**
     * RFC 5280 section 4.1.2.5.1 pivots at 50, PHP's own 'y' format pivots at 70.
     *
     * @return Iterator<string, array{string, string}>
     */
    public static function pivotProvider(): Iterator
    {
        yield '00 is 2000' => ['000101000000Z', '2000-01-01'];
        yield '49 is 2049' => ['490101000000Z', '2049-01-01'];
        yield '50 is 1950' => ['500101000000Z', '1950-01-01'];
        yield '69 is 1969' => ['690101000000Z', '1969-01-01'];
        yield '70 is 1970' => ['700101000000Z', '1970-01-01'];
        yield '99 is 1999' => ['990101000000Z', '1999-01-01'];
    }

    #[Test]
    #[DataProvider('pivotProvider')]
    public function centuryFollowsRfc5280(string $value, string $expected): void
    {
        $el = Element::fromDER("\x17" . chr(mb_strlen($value, '8bit')) . $value);
        static::assertSame($expected, $el->dateTime()->format('Y-m-d'));
    }

    /**
     * @return Iterator<string, array{string}>
     */
    public static function outOfRangeProvider(): Iterator
    {
        yield 'month 13' => ['991301000000Z'];
        yield 'day 32' => ['990132000000Z'];
        yield 'hour 25' => ['990101250000Z'];
        yield 'minute 61' => ['990101006100Z'];
        yield 'second 99' => ['990101000099Z'];
    }

    #[Test]
    #[DataProvider('outOfRangeProvider')]
    public function outOfRangeComponentsAreRejected(string $value): void
    {
        // createFromFormat() rolls these over silently: month 13 becomes January of the next year.
        $this->expectException(DecodeException::class);
        Element::fromDER("\x17" . chr(mb_strlen($value, '8bit')) . $value);
    }

    #[Test]
    public function roundTripAcrossThePivot(): void
    {
        foreach (['500101000000Z', '490101000000Z', '991231235959Z'] as $value) {
            $der = "\x17" . chr(mb_strlen($value, '8bit')) . $value;
            static::assertSame($der, Element::fromDER($der)->toDER(), $value);
        }
    }

    #[Test]
    public function generalizedTimeRejectsOutOfRangeComponents(): void
    {
        $value = '19991301000000Z';
        $this->expectException(DecodeException::class);
        Element::fromDER("\x18" . chr(mb_strlen($value, '8bit')) . $value);
    }

    #[Test]
    public function pivotConstantMatchesTheRfc(): void
    {
        static::assertSame(50, UTCTime::CENTURY_PIVOT);
    }
}
