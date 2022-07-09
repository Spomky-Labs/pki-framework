<?php

declare(strict_types = 1);

namespace Sop\Test\ASN1\Type\Primitive\GeneralizedTime;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\GeneralizedTime;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\TimeType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * @group type
 * @group generalized-time
 *
 * @internal
 */
class GeneralizedTimeTest extends TestCase
{
    public function testCreate()
    {
        $el = GeneralizedTime::fromString('Mon Jan 2 15:04:05 MST 2006');
        $this->assertInstanceOf(GeneralizedTime::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     */
    public function testTag(Element $el)
    {
        $this->assertEquals(Element::TYPE_GENERALIZED_TIME, $el->tag());
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testEncode
     */
    public function testDecode(string $data): GeneralizedTime
    {
        $el = GeneralizedTime::fromDER($data);
        $this->assertInstanceOf(GeneralizedTime::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(TimeType $ref, TimeType $el)
    {
        $this->assertEquals($ref->dateTime()
            ->getTimestamp(), $el->dateTime()
            ->getTimestamp());
    }

    /**
     * @depends testCreate
     */
    public function testWrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(GeneralizedTime::class,
            $wrap->asGeneralizedTime());
    }

    public function testWrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(
            'GeneralizedTime expected, got primitive NULL');
        $wrap->asGeneralizedTime();
    }

    /**
     * @depends testCreate
     */
    public function testClone(Element $el)
    {
        $clone = clone $el;
        $this->assertInstanceOf(GeneralizedTime::class, $clone);
    }

    /**
     * @depends testCreate
     */
    public function testStringable(TimeType $time)
    {
        $this->assertEquals('20060102220405Z', $time->string());
        $this->assertEquals('20060102220405Z', strval($time));
    }

    /**
     * Test bug where leading zeroes in fraction gets stripped,
     * such that `.05` becomes `.5`.
     */
    public function testLeadingFractionZeroes()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = \DateTimeImmutable::createFromFormat('U.u', "{$ts}.05",
            new \DateTimeZone('UTC'));
        $el = new GeneralizedTime($dt);
        $str = $el->string();
        $der = $el->toDER();
        $el = GeneralizedTime::fromDER($der);
        $this->assertEquals($str, $el->string());
    }
}
