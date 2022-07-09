<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\CertPolicy;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use Sop\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

/**
 * @internal
 */
final class PolicyInformationTest extends TestCase
{
    public const OID = '1.3.6.1.3';

    /**
     * @test
     */
    public function createWithCPS()
    {
        $pi = new PolicyInformation(self::OID, new CPSQualifier('urn:test'));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function encodeWithCPS(PolicyInformation $pi)
    {
        $el = $pi->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encodeWithCPS
     *
     * @param string $data
     *
     * @test
     */
    public function decodeWithCPS($data)
    {
        $pi = PolicyInformation::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends createWithCPS
     * @depends decodeWithCPS
     *
     * @test
     */
    public function recodedWithCPS(PolicyInformation $ref, PolicyInformation $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function oID(PolicyInformation $pi)
    {
        $this->assertEquals(self::OID, $pi->oid());
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function has(PolicyInformation $pi)
    {
        $this->assertTrue($pi->has(CPSQualifier::OID_CPS));
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function hasNot(PolicyInformation $pi)
    {
        $this->assertFalse($pi->has('1.3.6.1.3'));
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function get(PolicyInformation $pi)
    {
        $this->assertInstanceOf(PolicyQualifierInfo::class, $pi->get(CPSQualifier::OID_CPS));
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function getFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->get('1.3.6.1.3');
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function cPSQualifier(PolicyInformation $pi)
    {
        $this->assertInstanceOf(CPSQualifier::class, $pi->CPSQualifier());
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function userNoticeQualifierFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->userNoticeQualifier();
    }

    /**
     * @test
     */
    public function createWithNotice()
    {
        $pi = new PolicyInformation(self::OID, new UserNoticeQualifier(DisplayText::fromString('notice')));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends createWithNotice
     *
     * @test
     */
    public function cPSQualifierFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->CPSQualifier();
    }

    /**
     * @depends createWithNotice
     *
     * @test
     */
    public function userNoticeQualifier(PolicyInformation $pi)
    {
        $this->assertInstanceOf(UserNoticeQualifier::class, $pi->userNoticeQualifier());
    }

    /**
     * @test
     */
    public function createWithMultiple()
    {
        $pi = new PolicyInformation(
            self::OID,
            new CPSQualifier('urn:test'),
            new UserNoticeQualifier(DisplayText::fromString('notice'))
        );
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends createWithMultiple
     *
     * @test
     */
    public function encodeWithMultiple(PolicyInformation $pi)
    {
        $el = $pi->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encodeWithMultiple
     *
     * @param string $data
     *
     * @test
     */
    public function decodeWithMultiple($data)
    {
        $pi = PolicyInformation::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends createWithMultiple
     * @depends decodeWithMultiple
     *
     * @test
     */
    public function recodedMultiple(PolicyInformation $ref, PolicyInformation $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends createWithMultiple
     *
     * @test
     */
    public function countMethod(PolicyInformation $pi)
    {
        $this->assertCount(2, $pi);
    }

    /**
     * @depends createWithMultiple
     *
     * @test
     */
    public function iterator(PolicyInformation $pi)
    {
        $values = [];
        foreach ($pi as $qual) {
            $values[] = $qual;
        }
        $this->assertContainsOnlyInstancesOf(PolicyQualifierInfo::class, $values);
    }

    /**
     * @test
     */
    public function isAnyPolicy()
    {
        $pi = new PolicyInformation(PolicyInformation::OID_ANY_POLICY);
        $this->assertTrue($pi->isAnyPolicy());
    }
}
