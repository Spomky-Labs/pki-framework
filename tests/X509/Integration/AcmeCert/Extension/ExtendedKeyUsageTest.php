<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use Sop\X509\Certificate\Extension\Extension;

/**
 * @internal
 */
final class ExtendedKeyUsageTest extends RefExtTestHelper
{
    /**
     * @return ExtendedKeyUsageExtension
     *
     * @test
     */
    public function extendedKeyUsageExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_EXT_KEY_USAGE);
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends extendedKeyUsageExtension
     *
     * @test
     */
    public function usage(ExtendedKeyUsageExtension $eku)
    {
        $this->assertTrue($eku->has(ExtendedKeyUsageExtension::OID_SERVER_AUTH));
        $this->assertTrue($eku->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }
}
