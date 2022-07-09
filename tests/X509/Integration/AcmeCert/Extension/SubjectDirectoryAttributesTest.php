<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X501\ASN1\AttributeType;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectDirectoryAttributesExtension;

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
