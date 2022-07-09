<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\X509\Certificate\Extension\CertificatePoliciesExtension;
use Sop\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use Sop\X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use Sop\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extensions;
use UnexpectedValueException;

/**
 * @internal
 */
final class CertificatePoliciesTest extends TestCase
{
    final public const INFO_OID = '1.3.6.1.3';

    final public const CPS_URI = 'urn:test';

    final public const NOTICE_TXT = 'Notice';

    final public const REF_ORG = 'ACME Ltd.';

    /**
     * @test
     */
    public function createCPS()
    {
        $qual = new CPSQualifier('urn:test');
        $this->assertInstanceOf(PolicyQualifierInfo::class, $qual);
        return $qual;
    }

    /**
     * @test
     */
    public function createNotice()
    {
        $qual = new UserNoticeQualifier(
            DisplayText::fromString('Notice'),
            new NoticeReference(DisplayText::fromString(self::REF_ORG), 1, 2, 3)
        );
        $this->assertInstanceOf(PolicyQualifierInfo::class, $qual);
        return $qual;
    }

    /**
     * @depends createCPS
     * @depends createNotice
     *
     * @test
     */
    public function createPolicyInfo(PolicyQualifierInfo $q1, PolicyQualifierInfo $q2)
    {
        $info = new PolicyInformation(self::INFO_OID, $q1, $q2);
        $this->assertInstanceOf(PolicyInformation::class, $info);
        return $info;
    }

    /**
     * @depends createPolicyInfo
     *
     * @test
     */
    public function create(PolicyInformation $info)
    {
        $ext = new CertificatePoliciesExtension(true, $info, new PolicyInformation('1.3.6.1.3.10'));
        $this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_CERTIFICATE_POLICIES, $ext->oid());
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
        $ext = CertificatePoliciesExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
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
    public function countMethod(CertificatePoliciesExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(CertificatePoliciesExtension $ext)
    {
        $values = [];
        foreach ($ext as $info) {
            $values[] = $info;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(PolicyInformation::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function getFail(CertificatePoliciesExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->get('1.2.3');
    }

    /**
     * @test
     */
    public function hasAnyPolicy()
    {
        $ext = new CertificatePoliciesExtension(true, new PolicyInformation(PolicyInformation::OID_ANY_POLICY));
        $this->assertTrue($ext->hasAnyPolicy());
    }

    /**
     * @test
     */
    public function anyPolicyFail()
    {
        $ext = new CertificatePoliciesExtension(true, new PolicyInformation('1.3.6.1.3'));
        $this->expectException(LogicException::class);
        $ext->anyPolicy();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function info(CertificatePoliciesExtension $ext)
    {
        $info = $ext->get(self::INFO_OID);
        $this->assertInstanceOf(PolicyInformation::class, $info);
        return $info;
    }

    /**
     * @depends info
     *
     * @test
     */
    public function infoCount(PolicyInformation $info)
    {
        $this->assertCount(2, $info);
    }

    /**
     * @depends info
     *
     * @test
     */
    public function infoIterator(PolicyInformation $info)
    {
        $values = [];
        foreach ($info as $qual) {
            $values[] = $qual;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(PolicyQualifierInfo::class, $values);
    }

    /**
     * @depends info
     *
     * @test
     */
    public function cPS(PolicyInformation $info)
    {
        $qual = $info->CPSQualifier();
        $this->assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends cPS
     *
     * @test
     */
    public function cPSURI(CPSQualifier $cps)
    {
        $this->assertEquals(self::CPS_URI, $cps->uri());
    }

    /**
     * @depends info
     *
     * @test
     */
    public function userNotice(PolicyInformation $info)
    {
        $qual = $info->userNoticeQualifier();
        $this->assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends userNotice
     *
     * @test
     */
    public function userNoticeExplicit(UserNoticeQualifier $notice)
    {
        $this->assertEquals(self::NOTICE_TXT, $notice->explicitText());
    }

    /**
     * @depends userNotice
     *
     * @test
     */
    public function userNoticeRef(UserNoticeQualifier $notice)
    {
        $ref = $notice->noticeRef();
        $this->assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends userNoticeRef
     *
     * @test
     */
    public function refOrg(NoticeReference $ref)
    {
        $this->assertEquals(self::REF_ORG, $ref->organization());
    }

    /**
     * @depends userNoticeRef
     *
     * @test
     */
    public function refNumbers(NoticeReference $ref)
    {
        $this->assertEquals([1, 2, 3], $ref->numbers());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(CertificatePoliciesExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasCertificatePolicies());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->certificatePolicies();
        $this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
    }

    /**
     * @test
     */
    public function encodeEmptyFail()
    {
        $ext = new CertificatePoliciesExtension(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    /**
     * @test
     */
    public function decodeEmptyFail()
    {
        $seq = new Sequence();
        $ext_seq = new Sequence(
            new ObjectIdentifier(Extension::OID_CERTIFICATE_POLICIES),
            new OctetString($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        CertificatePoliciesExtension::fromASN1($ext_seq);
    }
}
