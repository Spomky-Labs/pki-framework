<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\CertPolicy;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

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
        $pi = PolicyInformation::create(self::OID, CPSQualifier::create('urn:test'));
        static::assertInstanceOf(PolicyInformation::class, $pi);
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
        static::assertInstanceOf(Sequence::class, $el);
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
        static::assertInstanceOf(PolicyInformation::class, $pi);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function oID(PolicyInformation $pi)
    {
        static::assertEquals(self::OID, $pi->oid());
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function has(PolicyInformation $pi)
    {
        static::assertTrue($pi->has(CPSQualifier::OID_CPS));
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function hasNot(PolicyInformation $pi)
    {
        static::assertFalse($pi->has('1.3.6.1.3'));
    }

    /**
     * @depends createWithCPS
     *
     * @test
     */
    public function get(PolicyInformation $pi)
    {
        static::assertInstanceOf(PolicyQualifierInfo::class, $pi->get(CPSQualifier::OID_CPS));
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
        static::assertInstanceOf(CPSQualifier::class, $pi->CPSQualifier());
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
        $pi = PolicyInformation::create(self::OID, UserNoticeQualifier::create(DisplayText::fromString('notice')));
        static::assertInstanceOf(PolicyInformation::class, $pi);
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
        static::assertInstanceOf(UserNoticeQualifier::class, $pi->userNoticeQualifier());
    }

    /**
     * @test
     */
    public function createWithMultiple()
    {
        $pi = PolicyInformation::create(
            self::OID,
            CPSQualifier::create('urn:test'),
            UserNoticeQualifier::create(DisplayText::fromString('notice'))
        );
        static::assertInstanceOf(PolicyInformation::class, $pi);
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
        static::assertInstanceOf(Sequence::class, $el);
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
        static::assertInstanceOf(PolicyInformation::class, $pi);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends createWithMultiple
     *
     * @test
     */
    public function countMethod(PolicyInformation $pi)
    {
        static::assertCount(2, $pi);
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
        static::assertContainsOnlyInstancesOf(PolicyQualifierInfo::class, $values);
    }

    /**
     * @test
     */
    public function isAnyPolicy()
    {
        $pi = PolicyInformation::create(PolicyInformation::OID_ANY_POLICY);
        static::assertTrue($pi->isAnyPolicy());
    }
}
