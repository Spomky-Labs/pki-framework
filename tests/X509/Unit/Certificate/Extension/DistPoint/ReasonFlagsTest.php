<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\ReasonFlags;

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
        $reasons = ReasonFlags::create(
            ReasonFlags::KEY_COMPROMISE | ReasonFlags::AFFILIATION_CHANGED |
            ReasonFlags::CESSATION_OF_OPERATION |
            ReasonFlags::PRIVILEGE_WITHDRAWN
        );
        static::assertInstanceOf(ReasonFlags::class, $reasons);
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
        static::assertInstanceOf(BitString::class, $el);
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
        static::assertInstanceOf(ReasonFlags::class, $reasons);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyCompromise(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isKeyCompromise());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function cACompromise(ReasonFlags $reasons)
    {
        static::assertFalse($reasons->isCACompromise());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function affiliationChanged(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isAffiliationChanged());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function superseded(ReasonFlags $reasons)
    {
        static::assertFalse($reasons->isSuperseded());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function cessationOfOperation(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isCessationOfOperation());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function certificateHold(ReasonFlags $reasons)
    {
        static::assertFalse($reasons->isCertificateHold());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function priviligeWhitdrawn(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isPrivilegeWithdrawn());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function aACompromise(ReasonFlags $reasons)
    {
        static::assertFalse($reasons->isAACompromise());
    }
}
