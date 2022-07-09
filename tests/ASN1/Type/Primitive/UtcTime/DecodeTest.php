<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\UtcTime;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\UTCTime;

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
        $el = UTCTime::fromDER("\x17\x0d" . '060102220405Z');
        static::assertInstanceOf(UTCTime::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $date = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $el = UTCTime::fromDER("\x17\x0d" . '060102220405Z');
        static::assertEquals($date, $el->dateTime() ->getTimestamp());
    }

    /**
     * @test
     */
    public function withoutSeconds()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x0b" . '0601022204Z');
    }

    /**
     * @test
     */
    public function withTimezone()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x11" . '060102150405+0700');
    }

    /**
     * @test
     */
    public function empty()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x0");
    }

    /**
     * @test
     */
    public function invalidFormat()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x0d" . 'o60102220405Z');
    }

    /**
     * @test
     */
    public function noTimezone()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid UTCTime format');
        UTCTime::fromDER("\x17\x0c" . '060102220405');
    }
}
