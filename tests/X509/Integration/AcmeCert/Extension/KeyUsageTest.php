<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;

/**
 * @internal
 */
final class KeyUsageTest extends RefExtTestHelper
{
    #[Test]
    public function keyUsage(): KeyUsageExtension
    {
        $ext = self::$_extensions->get(Extension::OID_KEY_USAGE);
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('keyUsage')]
    public function keyUsageBits(KeyUsageExtension $ku)
    {
        static::assertFalse($ku->isDigitalSignature());
        static::assertFalse($ku->isNonRepudiation());
        static::assertTrue($ku->isKeyEncipherment());
        static::assertFalse($ku->isDataEncipherment());
        static::assertFalse($ku->isKeyAgreement());
        static::assertTrue($ku->isKeyCertSign());
        static::assertFalse($ku->isCRLSign());
        static::assertFalse($ku->isEncipherOnly());
        static::assertFalse($ku->isDecipherOnly());
    }
}
