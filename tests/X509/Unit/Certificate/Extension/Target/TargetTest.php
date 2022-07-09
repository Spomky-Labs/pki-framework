<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Target;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetGroup;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetName;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\RFC822Name;
use UnexpectedValueException;

/**
 * @internal
 */
final class TargetTest extends TestCase
{
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
