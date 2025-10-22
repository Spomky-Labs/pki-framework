<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\GeneralizedTime;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\TimeType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class GeneralizedTimeTest extends TestCase
{
    #[Test]
    public function create(): GeneralizedTime
    {
        $el = GeneralizedTime::fromString('Mon Jan 2 15:04:05 MST 2006');
        static::assertInstanceOf(GeneralizedTime::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_GENERALIZED_TIME, $el->tag());
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
    public function decode(string $data): GeneralizedTime
    {
        $el = GeneralizedTime::fromDER($data);
        static::assertInstanceOf(GeneralizedTime::class, $el);
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
        static::assertInstanceOf(GeneralizedTime::class, $wrap->asGeneralizedTime());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('GeneralizedTime expected, got primitive NULL');
        $wrap->asGeneralizedTime();
    }

    #[Test]
    #[Depends('create')]
    public function clone(Element $el)
    {
        $clone = clone $el;
        static::assertInstanceOf(GeneralizedTime::class, $clone);
    }

    #[Test]
    #[Depends('create')]
    public function stringable(TimeType $time)
    {
        static::assertSame('20060102220405Z', $time->string());
        static::assertSame('20060102220405Z', strval($time));
    }

    /**
     * Test bug where leading zeroes in fraction gets stripped, such that `.05` becomes `.5`.
     */
    #[Test]
    public function leadingFractionZeroes()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.05", new DateTimeZone('UTC'));
        $el = GeneralizedTime::create($dt);
        $str = $el->string();
        $der = $el->toDER();
        $el = GeneralizedTime::fromDER($der);
        static::assertSame($str, $el->string());
    }
}
