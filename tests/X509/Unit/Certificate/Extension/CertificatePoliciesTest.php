<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePoliciesExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
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

    #[Test]
    public function createCPS(): CPSQualifier
    {
        $qual = CPSQualifier::create('urn:test');
        static::assertInstanceOf(PolicyQualifierInfo::class, $qual);
        return $qual;
    }

    #[Test]
    public function createNotice(): UserNoticeQualifier
    {
        $qual = UserNoticeQualifier::create(
            DisplayText::fromString('Notice'),
            NoticeReference::create(DisplayText::fromString(self::REF_ORG), 1, 2, 3)
        );
        static::assertInstanceOf(PolicyQualifierInfo::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('createCPS')]
    #[Depends('createNotice')]
    public function createPolicyInfo(PolicyQualifierInfo $q1, PolicyQualifierInfo $q2): PolicyInformation
    {
        $info = PolicyInformation::create(self::INFO_OID, $q1, $q2);
        static::assertInstanceOf(PolicyInformation::class, $info);
        return $info;
    }

    #[Test]
    #[Depends('createPolicyInfo')]
    public function create(PolicyInformation $info): CertificatePoliciesExtension
    {
        $ext = CertificatePoliciesExtension::create(true, $info, PolicyInformation::create('1.3.6.1.3.10'));
        static::assertInstanceOf(CertificatePoliciesExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_CERTIFICATE_POLICIES, $ext->oid());
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
        $ext = CertificatePoliciesExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(CertificatePoliciesExtension::class, $ext);
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
    public function countMethod(CertificatePoliciesExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(CertificatePoliciesExtension $ext)
    {
        $values = [];
        foreach ($ext as $info) {
            $values[] = $info;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(PolicyInformation::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function getFail(CertificatePoliciesExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->get('1.2.3');
    }

    #[Test]
    public function hasAnyPolicy()
    {
        $ext = CertificatePoliciesExtension::create(true, PolicyInformation::create(PolicyInformation::OID_ANY_POLICY));
        static::assertTrue($ext->hasAnyPolicy());
    }

    #[Test]
    public function anyPolicyFail()
    {
        $ext = CertificatePoliciesExtension::create(true, PolicyInformation::create('1.3.6.1.3'));
        $this->expectException(LogicException::class);
        $ext->anyPolicy();
    }

    #[Test]
    #[Depends('create')]
    public function info(CertificatePoliciesExtension $ext)
    {
        $info = $ext->get(self::INFO_OID);
        static::assertInstanceOf(PolicyInformation::class, $info);
        return $info;
    }

    #[Test]
    #[Depends('info')]
    public function infoCount(PolicyInformation $info)
    {
        static::assertCount(2, $info);
    }

    #[Test]
    #[Depends('info')]
    public function infoIterator(PolicyInformation $info)
    {
        $values = [];
        foreach ($info as $qual) {
            $values[] = $qual;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(PolicyQualifierInfo::class, $values);
    }

    #[Test]
    #[Depends('info')]
    public function cPS(PolicyInformation $info)
    {
        $qual = $info->CPSQualifier();
        static::assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('cPS')]
    public function cPSURI(CPSQualifier $cps)
    {
        static::assertSame(self::CPS_URI, $cps->uri());
    }

    #[Test]
    #[Depends('info')]
    public function userNotice(PolicyInformation $info)
    {
        $qual = $info->userNoticeQualifier();
        static::assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('userNotice')]
    public function userNoticeExplicit(UserNoticeQualifier $notice)
    {
        static::assertSame(self::NOTICE_TXT, $notice->explicitText()->string());
    }

    #[Test]
    #[Depends('userNotice')]
    public function userNoticeRef(UserNoticeQualifier $notice)
    {
        $ref = $notice->noticeRef();
        static::assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    #[Test]
    #[Depends('userNoticeRef')]
    public function refOrg(NoticeReference $ref)
    {
        static::assertSame(self::REF_ORG, $ref->organization()->string());
    }

    #[Test]
    #[Depends('userNoticeRef')]
    public function refNumbers(NoticeReference $ref)
    {
        static::assertSame([1, 2, 3], $ref->numbers());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(CertificatePoliciesExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasCertificatePolicies());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->certificatePolicies();
        static::assertInstanceOf(CertificatePoliciesExtension::class, $ext);
    }

    #[Test]
    public function encodeEmptyFail()
    {
        $ext = CertificatePoliciesExtension::create(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    #[Test]
    public function decodeEmptyFail()
    {
        $seq = Sequence::create();
        $ext_seq = Sequence::create(
            ObjectIdentifier::create(Extension::OID_CERTIFICATE_POLICIES),
            OctetString::create($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        CertificatePoliciesExtension::fromASN1($ext_seq);
    }
}
