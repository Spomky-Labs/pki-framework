<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\CertPolicy;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;

/**
 * @internal
 */
final class CPSQualifierTest extends TestCase
{
    public const URI = 'urn:test';

    public function testCreate()
    {
        $qual = new CPSQualifier(self::URI);
        $this->assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(CPSQualifier $qual)
    {
        $el = $qual->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $qual = CPSQualifier::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(CPSQualifier $ref, CPSQualifier $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testURI(CPSQualifier $qual)
    {
        $this->assertEquals(self::URI, $qual->uri());
    }

    /**
     * @depends testCreate
     */
    public function testOID(CPSQualifier $qual)
    {
        $this->assertEquals(CPSQualifier::OID_CPS, $qual->oid());
    }
}
