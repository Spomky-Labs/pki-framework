<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;

/**
 * @internal
 */
final class UnknownExtensionTest extends TestCase
{
    #[Test]
    public function createWithDER(): UnknownExtension
    {
        $ext = UnknownExtension::create('1.3.6.1.3.1', true, NullType::create());
        static::assertInstanceOf(UnknownExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('createWithDER')]
    public function extensionValueDER(UnknownExtension $ext)
    {
        $expect = (NullType::create())->toDER();
        static::assertSame($expect, $ext->extensionValue());
    }

    /**
     * @return UnknownExtension
     */
    #[Test]
    public function createFromString()
    {
        $ext = UnknownExtension::fromRawString('1.3.6.1.3.1', true, 'DATA');
        static::assertInstanceOf(UnknownExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('createFromString')]
    public function extensionValueRaw(UnknownExtension $ext)
    {
        static::assertSame('DATA', $ext->extensionValue());
    }

    #[Test]
    #[Depends('createWithDER')]
    public function extensionValueASN1(UnknownExtension $ext)
    {
        $cls = new ReflectionClass(UnknownExtension::class);
        $mtd = $cls->getMethod('valueASN1');
        $result = $mtd->invoke($ext);
        static::assertInstanceOf(Element::class, $result);
    }
}
