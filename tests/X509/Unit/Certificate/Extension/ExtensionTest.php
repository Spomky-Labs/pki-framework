<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use BadMethodCallException;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\UnknownExtension;

/**
 * @internal
 */
final class ExtensionTest extends TestCase
{
    /**
     * @test
     */
    public function fromDERBadCall()
    {
        $cls = new ReflectionClass(Extension::class);
        $mtd = $cls->getMethod('_fromDER');
        $mtd->setAccessible(true);
        $this->expectException(BadMethodCallException::class);
        $mtd->invoke(null, '', false);
    }

    /**
     * @test
     */
    public function extensionName()
    {
        $ext = new BasicConstraintsExtension(true, true);
        $this->assertEquals('basicConstraints', $ext->extensionName());
    }

    /**
     * @test
     */
    public function unknownExtensionName()
    {
        $ext = new UnknownExtension('1.3.6.1.3', false, new NullType());
        $this->assertEquals('1.3.6.1.3', $ext->extensionName());
    }

    /**
     * @test
     */
    public function toStringMethod()
    {
        $ext = new BasicConstraintsExtension(true, true);
        $this->assertEquals('basicConstraints', $ext);
    }
}
