<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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

    #[Test]
    public function create(): SubjectAlternativeNameExtension
    {
        $ext = SubjectAlternativeNameExtension::create(
            true,
            GeneralNames::create(DirectoryName::fromDNString(self::DN))
        );
        static::assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_SUBJECT_ALT_NAME, $ext->oid());
    }

    #[Test]
    #[Depends('create')]
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $ext = SubjectAlternativeNameExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function verifyName(?SubjectAlternativeNameExtension $ext = null)
    {
        static::assertSame(self::DN, $ext->names()->firstDN()->toString());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(SubjectAlternativeNameExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasSubjectAlternativeName());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->subjectAlternativeName();
        static::assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
    }
}
