<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use RuntimeException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\GeneralizedTime;
use Sop\ASN1\Type\Primitive\UTCTime;
use Sop\X509\Certificate\Time;
use UnexpectedValueException;

/**
 * @internal
 */
final class TimeTest extends TestCase
{
    final public const TIME = '2016-04-06 12:00:00';

    final public const TIME_GEN = '2050-01-01 12:00:00';

    /**
     * @test
     */
    public function create()
    {
        $time = Time::fromString(self::TIME);
        static::assertInstanceOf(Time::class, $time);
        return $time;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Time $time)
    {
        $seq = $time->toASN1();
        static::assertInstanceOf(UTCTime::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $time = Time::fromASN1(UTCTime::fromDER($der));
        static::assertInstanceOf(Time::class, $time);
        return $time;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Time $ref, Time $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function time(Time $time)
    {
        static::assertEquals(new DateTimeImmutable(self::TIME), $time->dateTime());
    }

    /**
     * @test
     */
    public function timezone()
    {
        $time = Time::fromString(self::TIME, 'UTC');
        static::assertEquals(new DateTimeImmutable(self::TIME, new DateTimeZone('UTC')), $time->dateTime());
    }

    /**
     * @test
     */
    public function createGeneralized()
    {
        $time = Time::fromString(self::TIME_GEN, 'UTC');
        static::assertInstanceOf(Time::class, $time);
        return $time;
    }

    /**
     * @depends createGeneralized
     *
     * @test
     */
    public function encodeGeneralized(Time $time)
    {
        $el = $time->toASN1();
        static::assertInstanceOf(GeneralizedTime::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encodeGeneralized
     *
     * @param string $der
     *
     * @test
     */
    public function decodeGeneralized($der)
    {
        $time = Time::fromASN1(GeneralizedTime::fromDER($der));
        static::assertInstanceOf(Time::class, $time);
        return $time;
    }

    /**
     * @depends createGeneralized
     * @depends decodeGeneralized
     *
     * @test
     */
    public function recodedGeneralized(Time $ref, Time $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @test
     */
    public function decodeFractional()
    {
        $dt = DateTimeImmutable::createFromFormat('!Y-m-d H:i:s.u', '2050-01-01 12:00:00.500');
        $time = new Time($dt);
        static::assertInstanceOf(GeneralizedTime::class, $time->toASN1());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function decodeUnknownTypeFail(Time $time)
    {
        $cls = new ReflectionClass($time);
        $prop = $cls->getProperty('_type');
        $prop->setAccessible(true);
        $prop->setValue($time, Element::TYPE_NULL);
        $this->expectException(UnexpectedValueException::class);
        $time->toASN1();
    }

    /**
     * @test
     */
    public function invalidDateFail()
    {
        $this->expectException(RuntimeException::class);
        Time::fromString('nope');
    }

    /**
     * @test
     */
    public function invalidTimezone()
    {
        $this->expectException(RuntimeException::class);
        Time::fromString('now', 'fail');
    }
}
