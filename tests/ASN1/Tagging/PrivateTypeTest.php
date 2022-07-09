<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\PrivateType;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class PrivateTypeTest extends TestCase
{
    /**
     * @test
     */
    public function implicitType()
    {
        // Data ::= [PRIVATE 1] IMPLICIT INTEGER
        $el = Element::fromDER("\xc1\x01\x2a");
        $this->assertInstanceOf(PrivateType::class, $el);
        return $el;
    }

    /**
     * @test
     */
    public function createImplicit()
    {
        $el = new ImplicitlyTaggedType(1, new Integer(42), Identifier::CLASS_PRIVATE);
        $this->assertEquals("\xc1\x01\x2a", $el->toDER());
    }

    /**
     * @depends implicitType
     *
     * @test
     */
    public function unwrapImplicit(PrivateType $el)
    {
        $inner = $el->implicit(Element::TYPE_INTEGER)->asInteger();
        $this->assertInstanceOf(Integer::class, $inner);
        return $inner;
    }

    /**
     * @depends unwrapImplicit
     *
     * @param int $el
     *
     * @test
     */
    public function implicitValue(Integer $el)
    {
        $this->assertEquals(42, $el->intNumber());
    }

    /**
     * @test
     */
    public function explicitType()
    {
        // Data ::= [PRIVATE 1] EXPLICIT INTEGER
        $el = Element::fromDER("\xe1\x03\x02\x01\x2a");
        $this->assertInstanceOf(PrivateType::class, $el);
        return $el;
    }

    /**
     * @test
     */
    public function createExplicit()
    {
        $el = new ExplicitlyTaggedType(1, new Integer(42), Identifier::CLASS_PRIVATE);
        $this->assertEquals("\xe1\x03\x02\x01\x2a", $el->toDER());
    }

    /**
     * @depends explicitType
     *
     * @test
     */
    public function unwrapExplicit(PrivateType $el)
    {
        $inner = $el->explicit()
            ->asInteger();
        $this->assertInstanceOf(Integer::class, $inner);
        return $inner;
    }

    /**
     * @depends unwrapExplicit
     *
     * @param int $el
     *
     * @test
     */
    public function explicitValue(Integer $el)
    {
        $this->assertEquals(42, $el->intNumber());
    }

    /**
     * @depends explicitType
     *
     * @test
     */
    public function recodeExplicit(PrivateType $el)
    {
        $der = $el->toDER();
        $this->assertEquals("\xe1\x03\x02\x01\x2a", $der);
    }

    /**
     * @test
     */
    public function fromUnspecified()
    {
        $el = UnspecifiedType::fromDER("\xc1\x01\x2a");
        $this->assertInstanceOf(PrivateType::class, $el->asPrivate());
    }

    /**
     * @test
     */
    public function fromUnspecifiedFail()
    {
        $el = UnspecifiedType::fromDER("\x5\0");
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Private type expected, got primitive NULL');
        $el->asPrivate();
    }
}
