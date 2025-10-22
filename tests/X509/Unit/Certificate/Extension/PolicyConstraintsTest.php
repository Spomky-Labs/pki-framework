<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;

/**
 * @internal
 */
final class PolicyConstraintsTest extends TestCase
{
    #[Test]
    public function create(): PolicyConstraintsExtension
    {
        $ext = PolicyConstraintsExtension::create(true, 2, 3);
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_POLICY_CONSTRAINTS, $ext->oid());
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
        $ext = PolicyConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
    public function requireExplicit(PolicyConstraintsExtension $ext)
    {
        static::assertSame(2, $ext->requireExplicitPolicy());
    }

    #[Test]
    #[Depends('create')]
    public function inhibitMapping(PolicyConstraintsExtension $ext)
    {
        static::assertSame(3, $ext->inhibitPolicyMapping());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(PolicyConstraintsExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasPolicyConstraints());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->policyConstraints();
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
    }

    #[Test]
    public function createEmpty()
    {
        $ext = PolicyConstraintsExtension::create(false);
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
        $ext = PolicyConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
    public function noRequireExplicitFail(PolicyConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->requireExplicitPolicy();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noInhibitMappingFail(PolicyConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->inhibitPolicyMapping();
    }
}
