<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Integer;

use Brick\Math\BigInteger;
use Brick\Math\Exception\IntegerOverflowException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;
use const PHP_INT_MAX;

/**
 * @internal
 */
final class IntegerTest extends TestCase
{
    #[Test]
    public function create(): void
    {
        $el = Integer::create(1);
        static::assertInstanceOf(Integer::class, $el);
        static::assertSame(Element::TYPE_INTEGER, $el->tag());

        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(Integer::class, $wrap->asInteger());
        static::assertSame(1, $el->intNumber());
    }

    #[Test]
    public function decode(): void
    {
        $el = Integer::create(1);
        $data = $el->toDER();
        $decoded = Integer::fromDER($data);
        static::assertInstanceOf(Integer::class, $decoded);
        static::assertEquals($el, $decoded);
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('INTEGER expected, got primitive NULL');
        $wrap->asInteger();
    }

    #[Test]
    public function intNumberOverflow()
    {
        $num = BigInteger::of(PHP_INT_MAX)->plus(1);
        $int = Integer::create($num);
        $this->expectException(IntegerOverflowException::class);
        $int->intNumber();
    }
}
