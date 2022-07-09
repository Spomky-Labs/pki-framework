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
    /**
     * @test
     */
    public function type()
    {
        $el = BaseString::fromDER("\x13\x0");
        static::assertInstanceOf(StringType::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $el = BaseString::fromDER("\x13\x0bHello World");
        static::assertEquals('Hello World', $el->string());
    }

    /**
     * @test
     */
    public function expectation()
    {
        $el = BaseString::fromDER("\x13\x0bHello World");
        static::assertInstanceOf(StringType::class, $el->expectType(Element::TYPE_STRING));
    }

    /**
     * Cover case where primitive string encoding is not primitive.
     *
     * @test
     */
    public function constructedFail()
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
