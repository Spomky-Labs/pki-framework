<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
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
        $el = new ImplicitlyTaggedType(2, new NullType());
        $this->expectException(UnexpectedValueException::class);
        DistributionPointName::fromTaggedType($el);
    }
}
