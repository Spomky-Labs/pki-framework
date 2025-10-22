<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\PrivateType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class PrivateTypeTest extends TestCase
{
    #[Test]
    public function implicitType(): PrivateType
    {
        // Data ::= [PRIVATE 1] IMPLICIT INTEGER
        $el = Element::fromDER("\xc1\x01\x2a");
        static::assertInstanceOf(PrivateType::class, $el);
        return $el;
    }

    #[Test]
    public function createImplicit()
    {
        $el = ImplicitlyTaggedType::create(1, Integer::create(42), Identifier::CLASS_PRIVATE);
        static::assertSame("\xc1\x01\x2a", $el->toDER());
    }

    #[Test]
    #[Depends('implicitType')]
    public function unwrapImplicit(PrivateType $el)
    {
        $inner = $el->implicit(Element::TYPE_INTEGER)->asInteger();
        static::assertInstanceOf(Integer::class, $inner);
        return $inner;
    }

    /**
     * @param int $el
     */
    #[Test]
    #[Depends('unwrapImplicit')]
    public function implicitValue(Integer $el)
    {
        static::assertSame(42, $el->intNumber());
    }

    #[Test]
    public function explicitType()
    {
        // Data ::= [PRIVATE 1] EXPLICIT INTEGER
        $el = Element::fromDER("\xe1\x03\x02\x01\x2a");
        static::assertInstanceOf(PrivateType::class, $el);
        return $el;
    }

    #[Test]
    public function createExplicit()
    {
        $el = ExplicitlyTaggedType::create(1, Integer::create(42), Identifier::CLASS_PRIVATE);
        static::assertSame("\xe1\x03\x02\x01\x2a", $el->toDER());
    }

    #[Test]
    #[Depends('explicitType')]
    public function unwrapExplicit(PrivateType $el)
    {
        $inner = $el->explicit()
            ->asInteger();
        static::assertInstanceOf(Integer::class, $inner);
        return $inner;
    }

    /**
     * @param int $el
     */
    #[Test]
    #[Depends('unwrapExplicit')]
    public function explicitValue(Integer $el)
    {
        static::assertSame(42, $el->intNumber());
    }

    #[Test]
    #[Depends('explicitType')]
    public function recodeExplicit(PrivateType $el)
    {
        $der = $el->toDER();
        static::assertSame("\xe1\x03\x02\x01\x2a", $der);
    }

    #[Test]
    public function fromUnspecified()
    {
        $el = UnspecifiedType::fromDER("\xc1\x01\x2a");
        static::assertInstanceOf(PrivateType::class, $el->asPrivate());
    }

    #[Test]
    public function fromUnspecifiedFail()
    {
        $el = UnspecifiedType::fromDER("\x5\0");
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Private type expected, got primitive NULL');
        $el->asPrivate();
    }
}
