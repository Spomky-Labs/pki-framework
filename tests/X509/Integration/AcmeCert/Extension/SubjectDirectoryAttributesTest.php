<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X501\ASN1\AttributeType;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectDirectoryAttributesExtension;

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class SubjectDirectoryAttributesTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return SubjectDirectoryAttributesExtension
     */
    public function testSubjectDirectoryAttributesExtension()
    {
        $ext = self::$_extensions->get(
            Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES);
        $this->assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testSubjectDirectoryAttributesExtension
     *
     * @param SubjectDirectoryAttributesExtension $sda
     */
    public function testSDADescription(SubjectDirectoryAttributesExtension $sda)
    {
        $desc = $sda->firstOf(AttributeType::OID_DESCRIPTION)
            ->first()
            ->stringValue();
        $this->assertEquals('A Company Manufacturing Everything', $desc);
    }
}
