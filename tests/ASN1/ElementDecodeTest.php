<?php

declare(strict_types=1);

namespace Sop\Test\ASN1;

use BadMethodCallException;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\NullType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ElementDecodeTest extends TestCase
{
    /**
     * @test
     */
    public function abstract()
    {
        $el = Element::fromDER("\x5\x0");
        $this->assertInstanceOf(NullType::class, $el);
    }

    /**
     * @test
     */
    public function concrete()
    {
        $el = NullType::fromDER("\x5\x0");
        $this->assertInstanceOf(NullType::class, $el);
    }

    /**
     * @test
     */
    public function concreteWrongClass()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage(Boolean::class . ' expected, got ' . NullType::class);
        Boolean::fromDER("\x5\x0");
    }

    /**
     * @test
     */
    public function unimplementedFail()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('not implemented');
        Element::fromDER("\x1f\x7f\x0");
    }

    /**
     * @test
     */
    public function expectTaggedFail()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Context specific element expected, got UNIVERSAL');
        Element::fromDER("\x5\x0")->expectTagged();
    }

    /**
     * @test
     */
    public function fromDERBadCall()
    {
        $cls = new ReflectionClass(Element::class);
        $mtd = $cls->getMethod('_decodeFromDER');
        $mtd->setAccessible(true);
        $identifier = new Identifier(Identifier::CLASS_UNIVERSAL, Identifier::PRIMITIVE, Element::TYPE_NULL);
        $offset = 0;
        $this->expectException(BadMethodCallException::class);
        $this->expectExceptionMessage('must be implemented in derived class');
        $mtd->invokeArgs(null, [$identifier, '', &$offset]);
    }

    /**
     * @test
     */
    public function fromUnimplementedClass()
    {
        $cls = new ReflectionClass(Element::class);
        $mtd = $cls->getMethod('_determineImplClass');
        $mtd->setAccessible(true);
        $identifier = new ElementDecodeTest_IdentifierMockup(0, 0, 0);
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('not implemented');
        $mtd->invokeArgs(null, [$identifier]);
    }
}

class ElementDecodeTest_IdentifierMockup extends Identifier
{
    public function typeClass(): int
    {
        return 0xff;
    }
}
