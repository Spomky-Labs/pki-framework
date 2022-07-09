<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use Sop\X509\Certificate\Extension\NameConstraintsExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class NameConstraintsTest extends TestCase
{
    final public const PERMITTED_URI = '.example.com';

    final public const PERMITTED_DN = 'cn=Test';

    final public const EXCLUDED_URI = 'nope.example.com';

    /**
     * @test
     */
    public function createPermitted()
    {
        $subtrees = new GeneralSubtrees(
            new GeneralSubtree(new UniformResourceIdentifier(self::PERMITTED_URI)),
            new GeneralSubtree(DirectoryName::fromDNString(self::PERMITTED_DN))
        );
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @test
     */
    public function createExcluded()
    {
        $subtrees = new GeneralSubtrees(new GeneralSubtree(new UniformResourceIdentifier(self::EXCLUDED_URI)));
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends createPermitted
     * @depends createExcluded
     *
     * @test
     */
    public function create(GeneralSubtrees $permitted, GeneralSubtrees $excluded)
    {
        $ext = new NameConstraintsExtension(true, $permitted, $excluded);
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_NAME_CONSTRAINTS, $ext->oid());
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
        $ext = NameConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
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
    public function permitted(NameConstraintsExtension $ext)
    {
        $subtrees = $ext->permittedSubtrees();
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function excluded(NameConstraintsExtension $ext)
    {
        $subtrees = $ext->excludedSubtrees();
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends permitted
     *
     * @test
     */
    public function countMethod(GeneralSubtrees $subtrees)
    {
        static::assertCount(2, $subtrees);
    }

    /**
     * @depends permitted
     *
     * @test
     */
    public function iterator(GeneralSubtrees $subtrees)
    {
        $values = [];
        foreach ($subtrees as $subtree) {
            $values[] = $subtree;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(GeneralSubtree::class, $values);
    }

    /**
     * @depends permitted
     *
     * @test
     */
    public function permittedURI(GeneralSubtrees $subtrees)
    {
        static::assertEquals(self::PERMITTED_URI, $subtrees->all()[0] ->base() ->string());
    }

    /**
     * @depends permitted
     *
     * @test
     */
    public function permittedDN(GeneralSubtrees $subtrees)
    {
        static::assertEquals(self::PERMITTED_DN, $subtrees->all()[1] ->base() ->string());
    }

    /**
     * @depends excluded
     *
     * @test
     */
    public function excludedURI(GeneralSubtrees $subtrees)
    {
        static::assertEquals(self::EXCLUDED_URI, $subtrees->all()[0] ->base() ->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(NameConstraintsExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasNameConstraints());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->nameConstraints();
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
    }

    /**
     * @test
     */
    public function createEmpty()
    {
        $ext = new NameConstraintsExtension(false);
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function encodeEmpty(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encodeEmpty
     *
     * @param string $der
     *
     * @test
     */
    public function decodeEmpty($der)
    {
        $ext = NameConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends createEmpty
     * @depends decodeEmpty
     *
     * @test
     */
    public function recodedEmpty(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noPermittedSubtreesFail(NameConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->permittedSubtrees();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noExcludedSubtreesFail(NameConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->excludedSubtrees();
    }
}
