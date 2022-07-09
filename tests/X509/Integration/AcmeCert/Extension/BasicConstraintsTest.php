<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\BasicConstraintsExtension;

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class BasicConstraintsTest extends RefExtTestHelper
{
    /**
     * @return BasicConstraintsExtension
     */
    public function testBasicConstraintsExtension()
    {
        $ext = self::$_extensions->basicConstraints();
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testBasicConstraintsExtension
     */
    public function testBasicConstraintsCA(BasicConstraintsExtension $bc)
    {
        $this->assertTrue($bc->isCA());
    }

    /**
     * @depends testBasicConstraintsExtension
     */
    public function testBasicConstraintsPathLen(BasicConstraintsExtension $bc)
    {
        $this->assertEquals(3, $bc->pathLen());
    }
}
