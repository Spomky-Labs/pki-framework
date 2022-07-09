<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use BadMethodCallException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\UniformResourceIdentifier;
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
    public function fromChosenBadCall()
    {
        $this->expectException(BadMethodCallException::class);
        GeneralName::fromChosenASN1(new UnspecifiedType(new NullType()));
    }

    /**
     * @test
     */
    public function equals()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new UniformResourceIdentifier('urn:1');
        $this->assertTrue($n1->equals($n2));
    }

    /**
     * @test
     */
    public function notEquals()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new UniformResourceIdentifier('urn:2');
        $this->assertFalse($n1->equals($n2));
    }

    /**
     * @test
     */
    public function notEqualsDifferentTypes()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new DNSName('test');
        $this->assertFalse($n1->equals($n2));
    }
}
