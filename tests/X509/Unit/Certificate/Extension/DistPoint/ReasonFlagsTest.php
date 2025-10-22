<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\ReasonFlags;

/**
 * @internal
 */
final class ReasonFlagsTest extends TestCase
{
    public const URI = 'urn:test';

    #[Test]
    public function create(): ReasonFlags
    {
        $reasons = ReasonFlags::create(
            ReasonFlags::KEY_COMPROMISE | ReasonFlags::AFFILIATION_CHANGED |
            ReasonFlags::CESSATION_OF_OPERATION |
            ReasonFlags::PRIVILEGE_WITHDRAWN
        );
        static::assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    #[Test]
    #[Depends('create')]
    public function encode(ReasonFlags $reasons): string
    {
        $el = $reasons->toASN1();
        static::assertInstanceOf(BitString::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): ReasonFlags
    {
        $reasons = ReasonFlags::fromASN1(BitString::fromDER($data));
        static::assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(ReasonFlags $ref, ReasonFlags $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function keyCompromise(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isKeyCompromise());
    }

    #[Test]
    #[Depends('create')]
    public function cACompromise(ReasonFlags $reasons)
    {
        static::assertFalse($reasons->isCACompromise());
    }

    #[Test]
    #[Depends('create')]
    public function affiliationChanged(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isAffiliationChanged());
    }

    #[Test]
    #[Depends('create')]
    public function superseded(ReasonFlags $reasons)
    {
        static::assertFalse($reasons->isSuperseded());
    }

    #[Test]
    #[Depends('create')]
    public function cessationOfOperation(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isCessationOfOperation());
    }

    #[Test]
    #[Depends('create')]
    public function certificateHold(ReasonFlags $reasons)
    {
        static::assertFalse($reasons->isCertificateHold());
    }

    #[Test]
    #[Depends('create')]
    public function priviligeWhitdrawn(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isPrivilegeWithdrawn());
    }

    #[Test]
    #[Depends('create')]
    public function aACompromise(ReasonFlags $reasons)
    {
        static::assertFalse($reasons->isAACompromise());
    }
}
