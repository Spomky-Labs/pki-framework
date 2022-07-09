<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\GeneralizedTime;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\GeneralizedTime;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\TimeType;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class GeneralizedTimeTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = GeneralizedTime::fromString('Mon Jan 2 15:04:05 MST 2006');
        $this->assertInstanceOf(GeneralizedTime::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_GENERALIZED_TIME, $el->tag());
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
    public function decode(string $data): GeneralizedTime
    {
        $el = GeneralizedTime::fromDER($data);
        $this->assertInstanceOf(GeneralizedTime::class, $el);
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
        $this->assertInstanceOf(GeneralizedTime::class, $wrap->asGeneralizedTime());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('GeneralizedTime expected, got primitive NULL');
        $wrap->asGeneralizedTime();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function clone(Element $el)
    {
        $clone = clone $el;
        $this->assertInstanceOf(GeneralizedTime::class, $clone);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function stringable(TimeType $time)
    {
        $this->assertEquals('20060102220405Z', $time->string());
        $this->assertEquals('20060102220405Z', strval($time));
    }

    /**
     * Test bug where leading zeroes in fraction gets stripped, such that `.05` becomes `.5`.
     *
     * @test
     */
    public function leadingFractionZeroes()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.05", new DateTimeZone('UTC'));
        $el = new GeneralizedTime($dt);
        $str = $el->string();
        $der = $el->toDER();
        $el = GeneralizedTime::fromDER($der);
        $this->assertEquals($str, $el->string());
    }
}
