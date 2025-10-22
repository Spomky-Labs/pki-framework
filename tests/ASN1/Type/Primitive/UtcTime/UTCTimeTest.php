<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\UtcTime;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTCTime;
use SpomkyLabs\Pki\ASN1\Type\TimeType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class UTCTimeTest extends TestCase
{
    #[Test]
    public function create(): UTCTime
    {
        $el = UTCTime::fromString('Mon Jan 2 15:04:05 MST 2006');
        static::assertInstanceOf(UTCTime::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_UTC_TIME, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $data): UTCTime
    {
        $el = UTCTime::fromDER($data);
        static::assertInstanceOf(UTCTime::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(TimeType $ref, TimeType $el)
    {
        static::assertSame($ref->dateTime()->getTimestamp(), $el->dateTime()->getTimestamp());
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(UTCTime::class, $wrap->asUTCTime());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('UTCTime expected, got primitive NULL');
        $wrap->asUTCTime();
    }

    #[Test]
    #[Depends('create')]
    public function stringable(TimeType $time)
    {
        static::assertSame('060102220405Z', $time->string());
        static::assertSame('060102220405Z', strval($time));
    }
}
