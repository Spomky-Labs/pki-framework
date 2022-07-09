<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\PolicyConstraintsExtension;

/**
 * @internal
 */
final class PolicyConstraintsTest extends RefExtTestHelper
{
    /**
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
     */
    public function testRequireExplicitPolicy(PolicyConstraintsExtension $pc)
    {
        $this->assertEquals(3, $pc->requireExplicitPolicy());
    }

    /**
     * @depends testPolicyConstraintsExtension
     */
    public function testInhibitPolicyMapping(PolicyConstraintsExtension $pc)
    {
        $this->assertEquals(1, $pc->inhibitPolicyMapping());
    }
}
