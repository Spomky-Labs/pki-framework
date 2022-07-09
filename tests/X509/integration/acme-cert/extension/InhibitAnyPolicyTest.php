<?php

declare(strict_types=1);

namespace integration\acme-cert\extension;

use Extensions;
use integration\acmeuse;
use RefExtTestHelper;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\InhibitAnyPolicyExtension;

Sop\X509\Certificate\Extension\Extension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefInhibitAnyPolicyTest extends RefExtTestHelper
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
