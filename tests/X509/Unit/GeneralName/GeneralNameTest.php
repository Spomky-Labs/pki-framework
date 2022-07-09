<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class GeneralNameTest extends TestCase
{
    /**
     * @test
     */
    public function invalidTagFail()
    {
        $this->expectException(UnexpectedValueException::class);
        GeneralName::fromASN1(new ImplicitlyTaggedType(9, new NullType()));
    }

    /**
     * @test
     */
    public function equals()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new UniformResourceIdentifier('urn:1');
        static::assertTrue($n1->equals($n2));
    }

    /**
     * @test
     */
    public function notEquals()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new UniformResourceIdentifier('urn:2');
        static::assertFalse($n1->equals($n2));
    }

    /**
     * @test
     */
    public function notEqualsDifferentTypes()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new DNSName('test');
        static::assertFalse($n1->equals($n2));
    }
}
