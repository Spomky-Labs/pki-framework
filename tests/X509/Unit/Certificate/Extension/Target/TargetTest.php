<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function decodeTargetCertUnsupportedFail()
    {
        $this->expectException(RuntimeException::class);
        Target::fromASN1(ImplicitlyTaggedType::create(Target::TYPE_CERT, NullType::create()));
    }

    #[Test]
    public function decodeUnsupportedTagFail()
    {
        $this->expectException(UnexpectedValueException::class);
        Target::fromASN1(ImplicitlyTaggedType::create(3, NullType::create()));
    }

    #[Test]
    public function equals()
    {
        $t1 = TargetName::create(DNSName::create('n1'));
        $t2 = TargetName::create(DNSName::create('n1'));
        static::assertTrue($t1->equals($t2));
    }

    #[Test]
    public function notEquals()
    {
        $t1 = TargetName::create(DNSName::create('n1'));
        $t2 = TargetName::create(DNSName::create('n2'));
        static::assertFalse($t1->equals($t2));
    }

    #[Test]
    public function notEqualsDifferentEncoding()
    {
        $t1 = TargetName::create(DNSName::create('n1'));
        $t2 = TargetName::create(RFC822Name::create('n2'));
        static::assertFalse($t1->equals($t2));
    }

    #[Test]
    public function notEqualsDifferentType()
    {
        $t1 = TargetName::create(DNSName::create('n1'));
        $t2 = TargetGroup::create(DNSName::create('n1'));
        static::assertFalse($t1->equals($t2));
    }
}
