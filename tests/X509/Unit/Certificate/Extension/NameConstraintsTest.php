<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class NameConstraintsTest extends TestCase
{
    final public const PERMITTED_URI = '.example.com';

    final public const PERMITTED_DN = 'cn=Test';

    final public const EXCLUDED_URI = 'nope.example.com';

    #[Test]
    public function createPermitted(): GeneralSubtrees
    {
        $subtrees = GeneralSubtrees::create(
            GeneralSubtree::create(UniformResourceIdentifier::create(self::PERMITTED_URI)),
            GeneralSubtree::create(DirectoryName::fromDNString(self::PERMITTED_DN))
        );
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    #[Test]
    public function createExcluded(): GeneralSubtrees
    {
        $subtrees = GeneralSubtrees::create(
            GeneralSubtree::create(UniformResourceIdentifier::create(self::EXCLUDED_URI))
        );
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    #[Test]
    #[Depends('createPermitted')]
    #[Depends('createExcluded')]
    public function create(GeneralSubtrees $permitted, GeneralSubtrees $excluded): NameConstraintsExtension
    {
        $ext = NameConstraintsExtension::create(true, $permitted, $excluded);
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_NAME_CONSTRAINTS, $ext->oid());
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
        $ext = NameConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
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
    public function permitted(NameConstraintsExtension $ext)
    {
        $subtrees = $ext->permittedSubtrees();
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    #[Test]
    #[Depends('create')]
    public function excluded(NameConstraintsExtension $ext)
    {
        $subtrees = $ext->excludedSubtrees();
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    #[Test]
    #[Depends('permitted')]
    public function countMethod(GeneralSubtrees $subtrees)
    {
        static::assertCount(2, $subtrees);
    }

    #[Test]
    #[Depends('permitted')]
    public function iterator(GeneralSubtrees $subtrees)
    {
        $values = [];
        foreach ($subtrees as $subtree) {
            $values[] = $subtree;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(GeneralSubtree::class, $values);
    }

    #[Test]
    #[Depends('permitted')]
    public function permittedURI(GeneralSubtrees $subtrees)
    {
        static::assertSame(self::PERMITTED_URI, $subtrees->all()[0]->base()->string());
    }

    #[Test]
    #[Depends('permitted')]
    public function permittedDN(GeneralSubtrees $subtrees)
    {
        static::assertSame(self::PERMITTED_DN, $subtrees->all()[1]->base()->string());
    }

    #[Test]
    #[Depends('excluded')]
    public function excludedURI(GeneralSubtrees $subtrees)
    {
        static::assertSame(self::EXCLUDED_URI, $subtrees->all()[0]->base()->string());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(NameConstraintsExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasNameConstraints());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->nameConstraints();
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
    }

    #[Test]
    public function createEmpty()
    {
        $ext = NameConstraintsExtension::create(false);
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('createEmpty')]
    public function encodeEmpty(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encodeEmpty')]
    public function decodeEmpty($der)
    {
        $ext = NameConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('createEmpty')]
    #[Depends('decodeEmpty')]
    public function recodedEmpty(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noPermittedSubtreesFail(NameConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->permittedSubtrees();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noExcludedSubtreesFail(NameConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->excludedSubtrees();
    }
}
