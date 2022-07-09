<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use Sop\X509\Certificate\Extension\Extension;

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class ExtendedKeyUsageTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return ExtendedKeyUsageExtension
     */
    public function testExtendedKeyUsageExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_EXT_KEY_USAGE);
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testExtendedKeyUsageExtension
     *
     * @param ExtendedKeyUsageExtension $eku
     */
    public function testUsage(ExtendedKeyUsageExtension $eku)
    {
        $this->assertTrue($eku->has(ExtendedKeyUsageExtension::OID_SERVER_AUTH));
        $this->assertTrue(
            $eku->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }
}
