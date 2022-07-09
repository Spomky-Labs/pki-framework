<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;

/**
 * @internal
 */
final class ReasonFlagsTest extends TestCase
{
    public const URI = 'urn:test';

    /**
     * @test
     */
    public function create()
    {
        $reasons = new ReasonFlags(
            ReasonFlags::KEY_COMPROMISE | ReasonFlags::AFFILIATION_CHANGED |
            ReasonFlags::CESSATION_OF_OPERATION |
            ReasonFlags::PRIVILEGE_WITHDRAWN
        );
        $this->assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(ReasonFlags $reasons)
    {
        $el = $reasons->toASN1();
        $this->assertInstanceOf(BitString::class, $el);
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
        $reasons = ReasonFlags::fromASN1(BitString::fromDER($data));
        $this->assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(ReasonFlags $ref, ReasonFlags $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyCompromise(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isKeyCompromise());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function cACompromise(ReasonFlags $reasons)
    {
        $this->assertFalse($reasons->isCACompromise());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function affiliationChanged(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isAffiliationChanged());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function superseded(ReasonFlags $reasons)
    {
        $this->assertFalse($reasons->isSuperseded());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function cessationOfOperation(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isCessationOfOperation());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function certificateHold(ReasonFlags $reasons)
    {
        $this->assertFalse($reasons->isCertificateHold());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function priviligeWhitdrawn(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isPrivilegeWithdrawn());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function aACompromise(ReasonFlags $reasons)
    {
        $this->assertFalse($reasons->isAACompromise());
    }
}
