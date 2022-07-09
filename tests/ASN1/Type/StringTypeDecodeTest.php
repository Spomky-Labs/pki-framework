<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Element;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\BaseString;
use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\StringType;

/**
 * @internal
 */
final class StringTypeDecodeTest extends TestCase
{
    public function testType()
    {
        $el = BaseString::fromDER("\x13\x0");
        $this->assertInstanceOf(StringType::class, $el);
    }

    public function testValue()
    {
        $el = BaseString::fromDER("\x13\x0bHello World");
        $this->assertEquals('Hello World', $el->string());
    }

    public function testExpectation()
    {
        $el = BaseString::fromDER("\x13\x0bHello World");
        $this->assertInstanceOf(StringType::class, $el->expectType(Element::TYPE_STRING));
    }

    /**
     * Cover case where primitive string encoding is not primitive.
     */
    public function testConstructedFail()
    {
        $cls = new ReflectionClass(PrimitiveString::class);
        $mtd = $cls->getMethod('_decodeFromDER');
        $mtd->setAccessible(true);
        $identifier = new Identifier(
            Identifier::CLASS_UNIVERSAL,
            Identifier::CONSTRUCTED,
            Element::TYPE_OCTET_STRING
        );
        $offset = 0;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('must be primitive');
        $mtd->invokeArgs(null, [$identifier, "\x34\x0", &$offset]);
    }
}
