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
    public function testCreate()
    {
        $ext = new PolicyConstraintsExtension(true, 2, 3);
        $this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_POLICY_CONSTRAINTS, $ext->oid());
    }

    /**
     * @depends testCreate
     */
    public function testCritical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $ext = PolicyConstraintsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testRequireExplicit(PolicyConstraintsExtension $ext)
    {
        $this->assertEquals(2, $ext->requireExplicitPolicy());
    }

    /**
     * @depends testCreate
     */
    public function testInhibitMapping(PolicyConstraintsExtension $ext)
    {
        $this->assertEquals(3, $ext->inhibitPolicyMapping());
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(PolicyConstraintsExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasPolicyConstraints());
        return $extensions;
    }

    /**
     * @depends testExtensions
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->policyConstraints();
        $this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
    }

    public function testCreateEmpty()
    {
        $ext = new PolicyConstraintsExtension(false);
        $this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreateEmpty
     */
    public function testEncodeEmpty(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncodeEmpty
     *
     * @param string $der
     */
    public function testDecodeEmpty($der)
    {
        $ext = PolicyConstraintsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreateEmpty
     * @depends testDecodeEmpty
     */
    public function testRecodedEmpty(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreateEmpty
     */
    public function testNoRequireExplicitFail(PolicyConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->requireExplicitPolicy();
    }

    /**
     * @depends testCreateEmpty
     */
    public function testNoInhibitMappingFail(PolicyConstraintsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->inhibitPolicyMapping();
    }
}
