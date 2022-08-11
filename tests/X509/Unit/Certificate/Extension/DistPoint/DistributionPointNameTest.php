<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use UnexpectedValueException;

/**
 * @internal
 */
final class DistributionPointNameTest extends TestCase
{
    /**
     * @test
     */
    public function decodeUnsupportedTypeFail()
    {
        $el = new ImplicitlyTaggedType(2, NullType::create());
        $this->expectException(UnexpectedValueException::class);
        DistributionPointName::fromTaggedType($el);
    }
}
