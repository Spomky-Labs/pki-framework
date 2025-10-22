<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\IssuerAlternativeNameExtension;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class IssuerAlternativeNameTest extends RefExtTestHelper
{
    #[Test]
    public function issuerAlternativeName(): IssuerAlternativeNameExtension
    {
        $ext = self::$_extensions->get(Extension::OID_ISSUER_ALT_NAME);
        static::assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('issuerAlternativeName')]
    public function iANDirectoryName(IssuerAlternativeNameExtension $ian)
    {
        $dn = $ian->names()
            ->firstOf(GeneralName::TAG_DIRECTORY_NAME)
            ->dn()
            ->toString();
        static::assertSame('o=ACME Alternative Ltd.,c=FI,cn=ACME Wheel Intermediate', $dn);
    }
}
