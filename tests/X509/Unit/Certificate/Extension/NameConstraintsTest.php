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
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @test
     */
    public function createExcluded()
    {
        $subtrees = new GeneralSubtrees(new GeneralSubtree(new UniformResourceIdentifier(self::EXCLUDED_URI)));
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
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
        $this->assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_NAME_CONSTRAINTS, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
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
        $this->assertInstanceOf(NameConstraintsExtension::class, $ext);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function permitted(NameConstraintsExtension $ext)
    {
        $subtrees = $ext->permittedSubtrees();
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
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
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends permitted
     *
     * @test
     */
    public function countMethod(GeneralSubtrees $subtrees)
    {
        $this->assertCount(2, $subtrees);
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
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(GeneralSubtree::class, $values);
    }

    /**
     * @depends permitted
     *
     * @test
     */
    public function permittedURI(GeneralSubtrees $subtrees)
    {
        $this->assertEquals(self::PERMITTED_URI, $subtrees->all()[0] ->base() ->string());
    }

    /**
     * @depends permitted
     *
     * @test
     */
    public function permittedDN(GeneralSubtrees $subtrees)
    {
        $this->assertEquals(self::PERMITTED_DN, $subtrees->all()[1] ->base() ->string());
    }

    /**
     * @depends excluded
     *
     * @test
     */
    public function excludedURI(GeneralSubtrees $subtrees)
    {
        $this->assertEquals(self::EXCLUDED_URI, $subtrees->all()[0] ->base() ->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(NameConstraintsExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasNameConstraints());
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
        $this->assertInstanceOf(NameConstraintsExtension::class, $ext);
    }

    /**
     * @test
     */
    public function createEmpty()
    {
        $ext = new NameConstraintsExtension(false);
        $this->assertInstanceOf(NameConstraintsExtension::class, $ext);
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
        $this->assertInstanceOf(Sequence::class, $seq);
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
        $this->assertInstanceOf(NameConstraintsExtension::class, $ext);
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
        $this->assertEquals($ref, $new);
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
