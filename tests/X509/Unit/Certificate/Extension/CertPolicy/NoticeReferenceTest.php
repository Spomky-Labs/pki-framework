<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\CertPolicy;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use Sop\X509\Certificate\Extension\CertificatePolicy\NoticeReference;

/**
 * @group certificate
 * @group extension
 * @group certificate-policy
 *
 * @internal
 */
class NoticeReferenceTest extends TestCase
{
    public function testCreate()
    {
        $ref = new NoticeReference(DisplayText::fromString('org'), 1, 2, 3);
        $this->assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends testCreate
     *
     * @param NoticeReference $ref
     */
    public function testEncode(NoticeReference $ref)
    {
        $el = $ref->toASN1();
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
        $ref = NoticeReference::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param NoticeReference $ref
     * @param NoticeReference $new
     */
    public function testRecoded(NoticeReference $ref, NoticeReference $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param NoticeReference $ref
     */
    public function testOrganization(NoticeReference $ref)
    {
        $this->assertEquals('org', $ref->organization()
            ->string());
    }

    /**
     * @depends testCreate
     *
     * @param NoticeReference $ref
     */
    public function testNumbers(NoticeReference $ref)
    {
        $this->assertEquals([1, 2, 3], $ref->numbers());
    }
}
