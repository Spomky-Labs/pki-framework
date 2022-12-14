<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

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
    /**
     * @return UnknownExtension
     *
     * @test
     */
    public function createWithDER()
    {
        $ext = UnknownExtension::create('1.3.6.1.3.1', true, NullType::create());
        static::assertInstanceOf(UnknownExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends createWithDER
     *
     * @test
     */
    public function extensionValueDER(UnknownExtension $ext)
    {
        $expect = (NullType::create())->toDER();
        static::assertEquals($expect, $ext->extensionValue());
    }

    /**
     * @return UnknownExtension
     *
     * @test
     */
    public function createFromString()
    {
        $ext = UnknownExtension::fromRawString('1.3.6.1.3.1', true, 'DATA');
        static::assertInstanceOf(UnknownExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends createFromString
     *
     * @test
     */
    public function extensionValueRaw(UnknownExtension $ext)
    {
        static::assertEquals('DATA', $ext->extensionValue());
    }

    /**
     * @depends createWithDER
     *
     * @test
     */
    public function extensionValueASN1(UnknownExtension $ext)
    {
        $cls = new ReflectionClass(UnknownExtension::class);
        $mtd = $cls->getMethod('valueASN1');
        $mtd->setAccessible(true);
        $result = $mtd->invoke($ext);
        static::assertInstanceOf(Element::class, $result);
    }
}
