<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function invalidTagFail()
    {
        $this->expectException(UnexpectedValueException::class);
        GeneralName::fromASN1(ImplicitlyTaggedType::create(9, NullType::create()));
    }

    #[Test]
    public function equals()
    {
        $n1 = UniformResourceIdentifier::create('urn:1');
        $n2 = UniformResourceIdentifier::create('urn:1');
        static::assertTrue($n1->equals($n2));
    }

    #[Test]
    public function notEquals()
    {
        $n1 = UniformResourceIdentifier::create('urn:1');
        $n2 = UniformResourceIdentifier::create('urn:2');
        static::assertFalse($n1->equals($n2));
    }

    #[Test]
    public function notEqualsDifferentTypes()
    {
        $n1 = UniformResourceIdentifier::create('urn:1');
        $n2 = DNSName::create('test');
        static::assertFalse($n1->equals($n2));
    }
}
