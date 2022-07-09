<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\UnknownExtension;

/**
 * @internal
 */
final class ExtensionTest extends TestCase
{
    public function testFromDERBadCall()
    {
        $cls = new \ReflectionClass(Extension::class);
        $mtd = $cls->getMethod('_fromDER');
        $mtd->setAccessible(true);
        $this->expectException(\BadMethodCallException::class);
        $mtd->invoke(null, '', false);
    }

    public function testExtensionName()
    {
        $ext = new BasicConstraintsExtension(true, true);
        $this->assertEquals('basicConstraints', $ext->extensionName());
    }

    public function testUnknownExtensionName()
    {
        $ext = new UnknownExtension('1.3.6.1.3', false, new NullType());
        $this->assertEquals('1.3.6.1.3', $ext->extensionName());
    }

    public function testToString()
    {
        $ext = new BasicConstraintsExtension(true, true);
        $this->assertEquals('basicConstraints', $ext);
    }
}
