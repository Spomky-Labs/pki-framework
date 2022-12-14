<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectDirectoryAttributesExtension;

/**
 * @internal
 */
final class SubjectDirectoryAttributesTest extends RefExtTestHelper
{
    /**
     * @return SubjectDirectoryAttributesExtension
     *
     * @test
     */
    public function subjectDirectoryAttributesExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES);
        static::assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends subjectDirectoryAttributesExtension
     *
     * @test
     */
    public function sDADescription(SubjectDirectoryAttributesExtension $sda)
    {
        $desc = $sda->firstOf(AttributeType::OID_DESCRIPTION)
            ->first()
            ->stringValue();
        static::assertEquals('A Company Manufacturing Everything', $desc);
    }
}
