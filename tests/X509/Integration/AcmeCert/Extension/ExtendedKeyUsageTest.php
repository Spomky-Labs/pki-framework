<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use SpomkyLabs\Pki\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;

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
        static::assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends extendedKeyUsageExtension
     *
     * @test
     */
    public function usage(ExtendedKeyUsageExtension $eku)
    {
        static::assertTrue($eku->has(ExtendedKeyUsageExtension::OID_SERVER_AUTH));
        static::assertTrue($eku->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }
}
