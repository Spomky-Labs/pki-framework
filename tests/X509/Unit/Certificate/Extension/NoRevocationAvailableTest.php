<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\NoRevocationAvailableExtension;

/**
 * @internal
 */
final class NoRevocationAvailableTest extends TestCase
{
    public function testCreate()
    {
        $ext = new NoRevocationAvailableExtension(true);
        $this->assertInstanceOf(NoRevocationAvailableExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_NO_REV_AVAIL, $ext->oid());
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
        $ext = NoRevocationAvailableExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(NoRevocationAvailableExtension::class, $ext);
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
}
