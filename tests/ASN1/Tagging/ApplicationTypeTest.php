<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ApplicationType;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ApplicationTypeTest extends TestCase
{
    /**
     * @test
     */
    public function implicitType()
    {
        // Data ::= [APPLICATION 1] IMPLICIT INTEGER
        $el = Element::fromDER("\x41\x01\x2a");
        $this->assertInstanceOf(ApplicationType::class, $el);
        return $el;
    }

    /**
     * @test
     */
    public function createImplicit()
    {
        $el = new ImplicitlyTaggedType(1, new Integer(42), Identifier::CLASS_APPLICATION);
        $this->assertEquals("\x41\x01\x2a", $el->toDER());
    }

    /**
     * @depends implicitType
     *
     * @test
     */
    public function unwrapImplicit(ApplicationType $el)
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
        // Data ::= [APPLICATION 1] EXPLICIT INTEGER
        $el = Element::fromDER("\x61\x03\x02\x01\x2a");
        $this->assertInstanceOf(ApplicationType::class, $el);
        return $el;
    }

    /**
     * @test
     */
    public function createExplicit()
    {
        $el = new ExplicitlyTaggedType(1, new Integer(42), Identifier::CLASS_APPLICATION);
        $this->assertEquals("\x61\x03\x02\x01\x2a", $el->toDER());
    }

    /**
     * @depends explicitType
     *
     * @test
     */
    public function unwrapExplicit(ApplicationType $el)
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
    public function recodeExplicit(ApplicationType $el)
    {
        $der = $el->toDER();
        $this->assertEquals("\x61\x03\x02\x01\x2a", $der);
    }

    /**
     * @test
     */
    public function fromUnspecified()
    {
        $el = UnspecifiedType::fromDER("\x41\x01\x2a");
        $this->assertInstanceOf(ApplicationType::class, $el->asApplication());
    }

    /**
     * @test
     */
    public function fromUnspecifiedFail()
    {
        $el = UnspecifiedType::fromDER("\x5\0");
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Application type expected, got primitive NULL');
        $el->asApplication();
    }
}
