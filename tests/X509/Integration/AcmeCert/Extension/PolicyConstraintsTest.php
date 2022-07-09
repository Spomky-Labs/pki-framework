<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyConstraintsExtension;

/**
 * @internal
 */
final class PolicyConstraintsTest extends RefExtTestHelper
{
    /**
     * @return PolicyConstraintsExtension
     *
     * @test
     */
    public function policyConstraintsExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_POLICY_CONSTRAINTS);
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends policyConstraintsExtension
     *
     * @test
     */
    public function requireExplicitPolicy(PolicyConstraintsExtension $pc)
    {
        static::assertEquals(3, $pc->requireExplicitPolicy());
    }

    /**
     * @depends policyConstraintsExtension
     *
     * @test
     */
    public function inhibitPolicyMapping(PolicyConstraintsExtension $pc)
    {
        static::assertEquals(1, $pc->inhibitPolicyMapping());
    }
}
