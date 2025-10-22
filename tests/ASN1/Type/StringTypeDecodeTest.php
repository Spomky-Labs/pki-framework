<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\BaseString;
use SpomkyLabs\Pki\ASN1\Type\PrimitiveString;
use SpomkyLabs\Pki\ASN1\Type\StringType;

/**
 * @internal
 */
final class StringTypeDecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = BaseString::fromDER("\x13\x0");
        static::assertInstanceOf(StringType::class, $el);
    }

    #[Test]
    public function value()
    {
        $el = BaseString::fromDER("\x13\x0bHello World");
        static::assertSame('Hello World', $el->string());
    }

    #[Test]
    public function expectation()
    {
        $el = BaseString::fromDER("\x13\x0bHello World");
        static::assertInstanceOf(StringType::class, $el->expectType(Element::TYPE_STRING));
    }

    /**
     * Cover case where primitive string encoding is not primitive.
     */
    #[Test]
    public function constructedFail()
    {
        $cls = new ReflectionClass(PrimitiveString::class);
        $mtd = $cls->getMethod('decodeFromDER');
        $identifier = Identifier::create(
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
