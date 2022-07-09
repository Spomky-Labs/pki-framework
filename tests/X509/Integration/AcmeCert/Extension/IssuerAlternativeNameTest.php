<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\IssuerAlternativeNameExtension;
use Sop\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class IssuerAlternativeNameTest extends RefExtTestHelper
{
    /**
     * @return IssuerAlternativeNameExtension
     *
     * @test
     */
    public function issuerAlternativeName()
    {
        $ext = self::$_extensions->get(Extension::OID_ISSUER_ALT_NAME);
        $this->assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends issuerAlternativeName
     *
     * @test
     */
    public function iANDirectoryName(IssuerAlternativeNameExtension $ian)
    {
        $dn = $ian->names()
            ->firstOf(GeneralName::TAG_DIRECTORY_NAME)
            ->dn()
            ->toString();
        $this->assertEquals('o=ACME Alternative Ltd.,c=FI,cn=ACME Wheel Intermediate', $dn);
    }
}
