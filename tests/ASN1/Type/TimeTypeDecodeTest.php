<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\BaseTime;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\TimeType;
use UnexpectedValueException;

/**
 * @internal
 */
final class TimeTypeDecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = BaseTime::fromDER("\x17\x0d" . '060102220405Z');
        static::assertInstanceOf(TimeType::class, $el);
    }

    #[Test]
    public function value()
    {
        $date = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $el = BaseTime::fromDER("\x17\x0d" . '060102220405Z');
        static::assertSame($date, $el->dateTime()->getTimestamp());
    }

    #[Test]
    public function expectation()
    {
        $el = BaseTime::fromDER("\x17\x0d" . '060102220405Z');
        static::assertInstanceOf(TimeType::class, $el->expectType(Element::TYPE_TIME));
    }

    #[Test]
    public function expectationFails()
    {
        $el = NullType::create();
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Any Time expected, got NULL');
        $el->expectType(Element::TYPE_TIME);
    }
}
