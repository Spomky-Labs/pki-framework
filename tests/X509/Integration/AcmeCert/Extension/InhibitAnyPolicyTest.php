<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\InhibitAnyPolicyExtension;

/**
 * @internal
 */
final class InhibitAnyPolicyTest extends RefExtTestHelper
{
    /**
     * @return InhibitAnyPolicyExtension
     *
     * @test
     */
    public function inhibitAnyPolicyExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_INHIBIT_ANY_POLICY);
        static::assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends inhibitAnyPolicyExtension
     *
     * @test
     */
    public function skipCerts(InhibitAnyPolicyExtension $ext)
    {
        static::assertEquals(2, $ext->skipCerts());
    }
}
