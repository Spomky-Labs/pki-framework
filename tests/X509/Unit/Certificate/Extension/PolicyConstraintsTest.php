<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\PolicyConstraintsExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @internal
 */
final class PolicyConstraintsTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ext = new PolicyConstraintsExtension(true, 2, 3);
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_POLICY_CONSTRAINTS, $ext->oid());
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
        $ext = PolicyConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
    public function requireExplicit(PolicyConstraintsExtension $ext)
    {
        static::assertEquals(2, $ext->requireExplicitPolicy());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function inhibitMapping(PolicyConstraintsExtension $ext)
    {
        static::assertEquals(3, $ext->inhibitPolicyMapping());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(PolicyConstraintsExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasPolicyConstraints());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->policyConstraints();
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
    }

    /**
     * @test
     */
    public function createEmpty()
    {
        $ext = new PolicyConstraintsExtension(false);
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
        $ext = PolicyConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
    public function noRequireExplicitFail(PolicyConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->requireExplicitPolicy();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noInhibitMappingFail(PolicyConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->inhibitPolicyMapping();
    }
}
