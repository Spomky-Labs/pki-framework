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

    /**
     * @test
     */
    public function create()
    {
        $qual = new CPSQualifier(self::URI);
        $this->assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(CPSQualifier $qual)
    {
        $el = $qual->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $qual = CPSQualifier::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(CPSQualifier $ref, CPSQualifier $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function uRI(CPSQualifier $qual)
    {
        $this->assertEquals(self::URI, $qual->uri());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(CPSQualifier $qual)
    {
        $this->assertEquals(CPSQualifier::OID_CPS, $qual->oid());
    }
}
