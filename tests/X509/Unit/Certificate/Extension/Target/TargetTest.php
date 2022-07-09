<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\Target;

use BadMethodCallException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetGroup;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\RFC822Name;
use UnexpectedValueException;

/**
 * @internal
 */
final class TargetTest extends TestCase
{
    /**
     * @test
     */
    public function fromASN1BadCall()
    {
        $this->expectException(BadMethodCallException::class);
        Target::fromChosenASN1(new ImplicitlyTaggedType(0, new NullType()));
    }

    /**
     * @test
     */
    public function decodeTargetCertUnsupportedFail()
    {
        $this->expectException(RuntimeException::class);
        Target::fromASN1(new ImplicitlyTaggedType(Target::TYPE_CERT, new NullType()));
    }

    /**
     * @test
     */
    public function decodeUnsupportedTagFail()
    {
        $this->expectException(UnexpectedValueException::class);
        Target::fromASN1(new ImplicitlyTaggedType(3, new NullType()));
    }

    /**
     * @test
     */
    public function equals()
    {
        $t1 = new TargetName(new DNSName('n1'));
        $t2 = new TargetName(new DNSName('n1'));
        static::assertTrue($t1->equals($t2));
    }

    /**
     * @test
     */
    public function notEquals()
    {
        $t1 = new TargetName(new DNSName('n1'));
        $t2 = new TargetName(new DNSName('n2'));
        static::assertFalse($t1->equals($t2));
    }

    /**
     * @test
     */
    public function notEqualsDifferentEncoding()
    {
        $t1 = new TargetName(new DNSName('n1'));
        $t2 = new TargetName(new RFC822Name('n2'));
        static::assertFalse($t1->equals($t2));
    }

    /**
     * @test
     */
    public function notEqualsDifferentType()
    {
        $t1 = new TargetName(new DNSName('n1'));
        $t2 = new TargetGroup(new DNSName('n1'));
        static::assertFalse($t1->equals($t2));
    }
}
