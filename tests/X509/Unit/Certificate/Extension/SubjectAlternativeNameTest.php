<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class SubjectAlternativeNameTest extends TestCase
{
    final public const DN = 'cn=Alt name';

    /**
     * @test
     */
    public function create()
    {
        $ext = new SubjectAlternativeNameExtension(true, new GeneralNames(DirectoryName::fromDNString(self::DN)));
        static::assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_SUBJECT_ALT_NAME, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $ext = SubjectAlternativeNameExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(SubjectAlternativeNameExtension $ext)
    {
        static::assertEquals(self::DN, $ext->names()->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(SubjectAlternativeNameExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasSubjectAlternativeName());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->subjectAlternativeName();
        static::assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
    }
}
