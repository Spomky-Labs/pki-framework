<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\UnknownExtension;

/**
 * @internal
 */
final class ExtensionTest extends TestCase
{
    /**
     * @test
     */
    public function extensionName()
    {
        $ext = new BasicConstraintsExtension(true, true);
        static::assertEquals('basicConstraints', $ext->extensionName());
    }

    /**
     * @test
     */
    public function unknownExtensionName()
    {
        $ext = new UnknownExtension('1.3.6.1.3', false, new NullType());
        static::assertEquals('1.3.6.1.3', $ext->extensionName());
    }

    /**
     * @test
     */
    public function toStringMethod()
    {
        $ext = new BasicConstraintsExtension(true, true);
        static::assertEquals('basicConstraints', $ext);
    }
}
