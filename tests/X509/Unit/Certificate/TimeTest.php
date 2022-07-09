<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\GeneralizedTime;
use Sop\ASN1\Type\Primitive\UTCTime;
use Sop\X509\Certificate\Time;

/**
 * @group certificate
 * @group time
 *
 * @internal
 */
class TimeTest extends TestCase
{
    final public const TIME = '2016-04-06 12:00:00';

    final public const TIME_GEN = '2050-01-01 12:00:00';

    public function testCreate()
    {
        $time = Time::fromString(self::TIME);
        $this->assertInstanceOf(Time::class, $time);
        return $time;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Time $time)
    {
        $seq = $time->toASN1();
        $this->assertInstanceOf(UTCTime::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $time = Time::fromASN1(UTCTime::fromDER($der));
        $this->assertInstanceOf(Time::class, $time);
        return $time;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Time $ref, Time $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testTime(Time $time)
    {
        $this->assertEquals(
            new \DateTimeImmutable(self::TIME),
            $time->dateTime()
        );
    }

    public function testTimezone()
    {
        $time = Time::fromString(self::TIME, 'UTC');
        $this->assertEquals(
            new \DateTimeImmutable(self::TIME, new \DateTimeZone('UTC')),
            $time->dateTime()
        );
    }

    public function testCreateGeneralized()
    {
        $time = Time::fromString(self::TIME_GEN, 'UTC');
        $this->assertInstanceOf(Time::class, $time);
        return $time;
    }

    /**
     * @depends testCreateGeneralized
     */
    public function testEncodeGeneralized(Time $time)
    {
        $el = $time->toASN1();
        $this->assertInstanceOf(GeneralizedTime::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncodeGeneralized
     *
     * @param string $der
     */
    public function testDecodeGeneralized($der)
    {
        $time = Time::fromASN1(GeneralizedTime::fromDER($der));
        $this->assertInstanceOf(Time::class, $time);
        return $time;
    }

    /**
     * @depends testCreateGeneralized
     * @depends testDecodeGeneralized
     */
    public function testRecodedGeneralized(Time $ref, Time $new)
    {
        $this->assertEquals($ref, $new);
    }

    public function testDecodeFractional()
    {
        $dt = \DateTimeImmutable::createFromFormat(
            '!Y-m-d H:i:s.u',
            '2050-01-01 12:00:00.500'
        );
        $time = new Time($dt);
        $this->assertInstanceOf(GeneralizedTime::class, $time->toASN1());
    }

    /**
     * @depends testCreate
     */
    public function testDecodeUnknownTypeFail(Time $time)
    {
        $cls = new \ReflectionClass($time);
        $prop = $cls->getProperty('_type');
        $prop->setAccessible(true);
        $prop->setValue($time, Element::TYPE_NULL);
        $this->expectException(\UnexpectedValueException::class);
        $time->toASN1();
    }

    public function testInvalidDateFail()
    {
        $this->expectException(\RuntimeException::class);
        Time::fromString('nope');
    }

    public function testInvalidTimezone()
    {
        $this->expectException(\RuntimeException::class);
        Time::fromString('now', 'fail');
    }
}
