<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyConstraintsExtension;

/**
 * @internal
 */
final class PolicyConstraintsTest extends RefExtTestHelper
{
    #[Test]
    public function policyConstraintsExtension(): PolicyConstraintsExtension
    {
        $ext = self::$_extensions->get(Extension::OID_POLICY_CONSTRAINTS);
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('policyConstraintsExtension')]
    public function requireExplicitPolicy(PolicyConstraintsExtension $pc)
    {
        static::assertSame(3, $pc->requireExplicitPolicy());
    }

    #[Test]
    #[Depends('policyConstraintsExtension')]
    public function inhibitPolicyMapping(PolicyConstraintsExtension $pc)
    {
        static::assertSame(1, $pc->inhibitPolicyMapping());
    }
}
