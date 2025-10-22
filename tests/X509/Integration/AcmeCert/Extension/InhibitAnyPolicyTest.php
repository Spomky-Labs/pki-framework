<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\InhibitAnyPolicyExtension;

/**
 * @internal
 */
final class InhibitAnyPolicyTest extends RefExtTestHelper
{
    #[Test]
    public function inhibitAnyPolicyExtension(): InhibitAnyPolicyExtension
    {
        $ext = self::$_extensions->get(Extension::OID_INHIBIT_ANY_POLICY);
        static::assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('inhibitAnyPolicyExtension')]
    public function skipCerts(InhibitAnyPolicyExtension $ext)
    {
        static::assertSame(2, $ext->skipCerts());
    }
}
