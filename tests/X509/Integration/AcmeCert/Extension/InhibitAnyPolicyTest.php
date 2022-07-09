<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\InhibitAnyPolicyExtension;

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class InhibitAnyPolicyTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
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
     *
     * @param InhibitAnyPolicyExtension $ext
     */
    public function testSkipCerts(InhibitAnyPolicyExtension $ext)
    {
        $this->assertEquals(2, $ext->skipCerts());
    }
}
