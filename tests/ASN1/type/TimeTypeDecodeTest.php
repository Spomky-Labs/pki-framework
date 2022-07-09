<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\BaseTime;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\TimeType;

/**
 * @group decode
 * @group time
 *
 * @internal
 */
class TimeTypeDecodeTest extends TestCase
{
    public function testType()
    {
        $el = BaseTime::fromDER("\x17\x0d" . '060102220405Z');
        $this->assertInstanceOf(TimeType::class, $el);
    }

    public function testValue()
    {
        $date = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $el = BaseTime::fromDER("\x17\x0d" . '060102220405Z');
        $this->assertEquals($date, $el->dateTime()
            ->getTimestamp());
    }

    public function testExpectation()
    {
        $el = BaseTime::fromDER("\x17\x0d" . '060102220405Z');
        $this->assertInstanceOf(TimeType::class,
            $el->expectType(Element::TYPE_TIME));
    }

    public function testExpectationFails()
    {
        $el = new NullType();
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Any Time expected, got NULL');
        $el->expectType(Element::TYPE_TIME);
    }
}
