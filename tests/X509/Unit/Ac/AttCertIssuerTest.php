<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use UnexpectedValueException;

/**
 * @internal
 */
final class AttCertIssuerTest extends TestCase
{
    #[Test]
    public function v1FormFail()
    {
        $v1 = GeneralNames::create(DirectoryName::fromDNString('cn=Test'));
        $this->expectException(UnexpectedValueException::class);
        AttCertIssuer::fromASN1($v1->toASN1()->asUnspecified());
    }

    #[Test]
    public function unsupportedType()
    {
        $el = ImplicitlyTaggedType::create(1, NullType::create());
        $this->expectException(UnexpectedValueException::class);
        AttCertIssuer::fromASN1($el->asUnspecified());
    }
}
