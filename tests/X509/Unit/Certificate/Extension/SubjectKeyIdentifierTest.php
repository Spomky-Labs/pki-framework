<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

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

    /**
     * @test
     */
    public function create()
    {
        $ext = new SubjectKeyIdentifierExtension(true, self::KEY_ID);
        static::assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_SUBJECT_KEY_IDENTIFIER, $ext->oid());
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
        $ext = SubjectKeyIdentifierExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
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
    public function keyIdentifier(SubjectKeyIdentifierExtension $ext)
    {
        static::assertEquals(self::KEY_ID, $ext->keyIdentifier());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(SubjectKeyIdentifierExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasSubjectKeyIdentifier());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->subjectKeyIdentifier();
        static::assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
    }
}
