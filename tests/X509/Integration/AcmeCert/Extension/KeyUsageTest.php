<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;

/**
 * @internal
 */
final class KeyUsageTest extends RefExtTestHelper
{
    /**
     * @return KeyUsageExtension
     *
     * @test
     */
    public function keyUsage()
    {
        $ext = self::$_extensions->get(Extension::OID_KEY_USAGE);
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends keyUsage
     *
     * @test
     */
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
