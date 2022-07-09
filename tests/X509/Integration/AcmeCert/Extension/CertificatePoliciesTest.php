<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePoliciesExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;

/**
 * @internal
 */
final class CertificatePoliciesTest extends RefExtTestHelper
{
    /**
     * @return CertificatePoliciesExtension
     *
     * @test
     */
    public function certificatePoliciesExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_CERTIFICATE_POLICIES);
        static::assertInstanceOf(CertificatePoliciesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends certificatePoliciesExtension
     *
     * @return PolicyInformation
     *
     * @test
     */
    public function policyInformation(CertificatePoliciesExtension $cpe)
    {
        $pi = $cpe->get('1.3.6.1.4.1.45710.2.2.1');
        static::assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends policyInformation
     *
     * @return CPSQualifier
     *
     * @test
     */
    public function policyCPSQualifier(PolicyInformation $pi)
    {
        $cps = $pi->get(PolicyQualifierInfo::OID_CPS);
        static::assertInstanceOf(CPSQualifier::class, $cps);
        return $cps;
    }

    /**
     * @depends policyCPSQualifier
     *
     * @test
     */
    public function policyCPSQualifierURI(CPSQualifier $cps)
    {
        static::assertEquals('http://example.com/cps.html', $cps->uri());
    }

    /**
     * @depends policyInformation
     *
     * @return UserNoticeQualifier
     *
     * @test
     */
    public function policyUserNoticeQualifier(PolicyInformation $pi)
    {
        $un = $pi->get(PolicyQualifierInfo::OID_UNOTICE);
        static::assertInstanceOf(UserNoticeQualifier::class, $un);
        return $un;
    }

    /**
     * @depends policyUserNoticeQualifier
     *
     * @test
     */
    public function policyUserNoticeQualifierText(UserNoticeQualifier $un)
    {
        static::assertEquals('All your base are belong to us!', $un->explicitText() ->string());
    }

    /**
     * @depends policyUserNoticeQualifier
     *
     * @return NoticeReference
     *
     * @test
     */
    public function policyUserNoticeQualifierRef(UserNoticeQualifier $un)
    {
        $ref = $un->noticeRef();
        static::assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends policyUserNoticeQualifierRef
     *
     * @test
     */
    public function policyUserNoticeQualifierOrganization(NoticeReference $ref)
    {
        static::assertEquals('Toaplan Co., Ltd.', $ref->organization() ->string());
    }

    /**
     * @depends policyUserNoticeQualifierRef
     *
     * @test
     */
    public function policyUserNoticeQualifierNumbers(NoticeReference $ref)
    {
        static::assertEquals([1, 2], $ref->numbers());
    }
}
