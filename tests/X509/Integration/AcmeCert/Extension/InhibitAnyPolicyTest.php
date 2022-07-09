<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\InhibitAnyPolicyExtension;

/**
 * @internal
 */
final class InhibitAnyPolicyTest extends RefExtTestHelper
{
    /**
     * @return InhibitAnyPolicyExtension
     */
    public function testInhibitAnyPolicyExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_INHIBIT_ANY_POLICY);
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testInhibitAnyPolicyExtension
     */
    public function testSkipCerts(InhibitAnyPolicyExtension $ext)
    {
        $this->assertEquals(2, $ext->skipCerts());
    }
}
