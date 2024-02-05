<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;

/**
 * @internal
 */
final class ExtensionTest extends TestCase
{
    #[Test]
    public function extensionName()
    {
        $ext = BasicConstraintsExtension::create(true, true);
        static::assertSame('basicConstraints', $ext->extensionName());
    }

    #[Test]
    public function unknownExtensionName()
    {
        $ext = UnknownExtension::create('1.3.6.1.3', false, NullType::create());
        static::assertSame('1.3.6.1.3', $ext->extensionName());
    }

    #[Test]
    public function toStringMethod()
    {
        $ext = BasicConstraintsExtension::create(true, true);
        static::assertSame('basicConstraints', (string) $ext);
    }
}
