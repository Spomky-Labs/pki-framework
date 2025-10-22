<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;

/**
 * @internal
 */
final class ExtendedKeyUsageTest extends RefExtTestHelper
{
    #[Test]
    public function extendedKeyUsageExtension(): ExtendedKeyUsageExtension
    {
        $ext = self::$_extensions->get(Extension::OID_EXT_KEY_USAGE);
        static::assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('extendedKeyUsageExtension')]
    public function usage(ExtendedKeyUsageExtension $eku)
    {
        static::assertTrue($eku->has(ExtendedKeyUsageExtension::OID_SERVER_AUTH));
        static::assertTrue($eku->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }
}
