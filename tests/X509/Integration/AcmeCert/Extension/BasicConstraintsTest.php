<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;

/**
 * @internal
 */
final class BasicConstraintsTest extends RefExtTestHelper
{
    #[Test]
    public function basicConstraintsExtension(): BasicConstraintsExtension
    {
        $ext = self::$_extensions->basicConstraints();
        static::assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('basicConstraintsExtension')]
    public function basicConstraintsCA(BasicConstraintsExtension $bc)
    {
        static::assertTrue($bc->isCA());
    }

    #[Test]
    #[Depends('basicConstraintsExtension')]
    public function basicConstraintsPathLen(BasicConstraintsExtension $bc)
    {
        static::assertSame(3, $bc->pathLen());
    }
}
