<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;

/**
 * @internal
 */
final class SubjectKeyIdentifierTest extends TestCase
{
    final public const KEY_ID = 'test-id';

    #[Test]
    public function create(): SubjectKeyIdentifierExtension
    {
        $ext = SubjectKeyIdentifierExtension::create(true, self::KEY_ID);
        static::assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_SUBJECT_KEY_IDENTIFIER, $ext->oid());
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
        $ext = SubjectKeyIdentifierExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
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
    public function keyIdentifier(SubjectKeyIdentifierExtension $ext)
    {
        static::assertSame(self::KEY_ID, $ext->keyIdentifier());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(SubjectKeyIdentifierExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasSubjectKeyIdentifier());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->subjectKeyIdentifier();
        static::assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
    }
}
