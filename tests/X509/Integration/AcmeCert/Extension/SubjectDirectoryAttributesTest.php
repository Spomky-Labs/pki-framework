<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectDirectoryAttributesExtension;

/**
 * @internal
 */
final class SubjectDirectoryAttributesTest extends RefExtTestHelper
{
    #[Test]
    public function subjectDirectoryAttributesExtension(): SubjectDirectoryAttributesExtension
    {
        $ext = self::$_extensions->get(Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES);
        static::assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('subjectDirectoryAttributesExtension')]
    public function sDADescription(SubjectDirectoryAttributesExtension $sda)
    {
        $desc = $sda->firstOf(AttributeType::OID_DESCRIPTION)
            ->first()
            ->stringValue();
        static::assertSame('A Company Manufacturing Everything', $desc);
    }
}
