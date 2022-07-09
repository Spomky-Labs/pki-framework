<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\UtcTime;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\UTCTime;
use Sop\ASN1\Type\TimeType;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class UTCTimeTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = UTCTime::fromString('Mon Jan 2 15:04:05 MST 2006');
        $this->assertInstanceOf(UTCTime::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_UTC_TIME, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(string $data): UTCTime
    {
        $el = UTCTime::fromDER($data);
        $this->assertInstanceOf(UTCTime::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(TimeType $ref, TimeType $el)
    {
        $this->assertEquals($ref->dateTime() ->getTimestamp(), $el->dateTime() ->getTimestamp());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(UTCTime::class, $wrap->asUTCTime());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('UTCTime expected, got primitive NULL');
        $wrap->asUTCTime();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function stringable(TimeType $time)
    {
        $this->assertEquals('060102220405Z', $time->string());
        $this->assertEquals('060102220405Z', strval($time));
    }
}
