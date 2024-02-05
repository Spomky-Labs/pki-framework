<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\UtcTime;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTCTime;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = UTCTime::fromDER("\x17\x0d" . '060102220405Z');
        static::assertInstanceOf(UTCTime::class, $el);
    }

    #[Test]
    public function value()
    {
        $date = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $el = UTCTime::fromDER("\x17\x0d" . '060102220405Z');
        static::assertSame($date, $el->dateTime()->getTimestamp());
    }

    #[Test]
    public function withoutSeconds()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x0b" . '0601022204Z');
    }

    #[Test]
    public function withTimezone()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x11" . '060102150405+0700');
    }

    #[Test]
    public function empty()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x0");
    }

    #[Test]
    public function invalidFormat()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x0d" . 'o60102220405Z');
    }

    #[Test]
    public function noTimezone()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x0c" . '060102220405');
    }
}
