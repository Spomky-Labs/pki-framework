<?php

declare(strict_types=1);

namespace integration\acme-cert\extension;

use Extensions;
use integration\acmeuse;
use RefExtTestHelper;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;

Sop\X509\Certificate\Extension\BasicConstraintsExtension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefBasicConstraintsTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
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
     *
     * @param BasicConstraintsExtension $bc
     */
    public function testBasicConstraintsCA(BasicConstraintsExtension $bc)
    {
        $this->assertTrue($bc->isCA());
    }

    /**
     * @depends testBasicConstraintsExtension
     *
     * @param BasicConstraintsExtension $bc
     */
    public function testBasicConstraintsPathLen(BasicConstraintsExtension $bc)
    {
        $this->assertEquals(3, $bc->pathLen());
    }
}
