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
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends keyUsage
     *
     * @test
     */
    public function keyUsageBits(KeyUsageExtension $ku)
    {
        $this->assertFalse($ku->isDigitalSignature());
        $this->assertFalse($ku->isNonRepudiation());
        $this->assertTrue($ku->isKeyEncipherment());
        $this->assertFalse($ku->isDataEncipherment());
        $this->assertFalse($ku->isKeyAgreement());
        $this->assertTrue($ku->isKeyCertSign());
        $this->assertFalse($ku->isCRLSign());
        $this->assertFalse($ku->isEncipherOnly());
        $this->assertFalse($ku->isDecipherOnly());
    }
}
