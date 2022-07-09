<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\BasicConstraintsExtension;

/**
 * @internal
 */
final class BasicConstraintsTest extends RefExtTestHelper
{
    /**
     * @return BasicConstraintsExtension
     *
     * @test
     */
    public function basicConstraintsExtension()
    {
        $ext = self::$_extensions->basicConstraints();
        static::assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends basicConstraintsExtension
     *
     * @test
     */
    public function basicConstraintsCA(BasicConstraintsExtension $bc)
    {
        static::assertTrue($bc->isCA());
    }

    /**
     * @depends basicConstraintsExtension
     *
     * @test
     */
    public function basicConstraintsPathLen(BasicConstraintsExtension $bc)
    {
        static::assertEquals(3, $bc->pathLen());
    }
}
