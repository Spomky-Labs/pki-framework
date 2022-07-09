<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\AttributeCertificate\AttCertIssuer;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class AttCertIssuerTest extends TestCase
{
    public function testV1FormFail()
    {
        $v1 = new GeneralNames(DirectoryName::fromDNString('cn=Test'));
        $this->expectException(\UnexpectedValueException::class);
        AttCertIssuer::fromASN1($v1->toASN1()->asUnspecified());
    }

    public function testUnsupportedType()
    {
        $el = new ImplicitlyTaggedType(1, new NullType());
        $this->expectException(\UnexpectedValueException::class);
        AttCertIssuer::fromASN1($el->asUnspecified());
    }
}
