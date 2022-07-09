<?php

declare(strict_types=1);

namespace integration\acme-cert\extension;

use Extensions;
use integration\acmeuse;
use RefExtTestHelper;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\PolicyConstraintsExtension;

Sop\X509\Certificate\Extension\Extension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefPolicyConstraintsTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return PolicyConstraintsExtension
     */
    public function testPolicyConstraintsExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_POLICY_CONSTRAINTS);
        $this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testPolicyConstraintsExtension
     *
     * @param PolicyConstraintsExtension $pc
     */
    public function testRequireExplicitPolicy(PolicyConstraintsExtension $pc)
    {
        $this->assertEquals(3, $pc->requireExplicitPolicy());
    }

    /**
     * @depends testPolicyConstraintsExtension
     *
     * @param PolicyConstraintsExtension $pc
     */
    public function testInhibitPolicyMapping(PolicyConstraintsExtension $pc)
    {
        $this->assertEquals(1, $pc->inhibitPolicyMapping());
    }
}
