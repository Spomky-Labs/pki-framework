<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X501\ASN1\RDN;
use function strval;

/**
 * @internal
 */
final class NameTest extends TestCase
{
    #[Test]
    public function create(): Name
    {
        $name = Name::fromString('name=one,name=two');
        static::assertInstanceOf(Name::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Name $name): string
    {
        $der = $name->toASN1()
            ->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): Name
    {
        $name = Name::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Name::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Name $ref, Name $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function all(Name $name)
    {
        static::assertContainsOnlyInstancesOf(RDN::class, $name->all());
    }

    #[Test]
    #[Depends('create')]
    public function firstValueOf(Name $name)
    {
        static::assertSame('two', $name->firstValueOf('name')->stringValue());
    }

    #[Test]
    #[Depends('create')]
    public function firstValueOfNotFound(Name $name)
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Attribute cn not found');
        $name->firstValueOf('cn');
    }

    #[Test]
    public function firstValueOfMultipleFail()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('RDN with multiple name attributes');
        Name::fromString('name=one+name=two')->firstValueOf('name');
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(Name $name)
    {
        static::assertCount(2, $name);
    }

    #[Test]
    #[Depends('create')]
    public function countOfType(Name $name)
    {
        static::assertSame(2, $name->countOfType('name'));
    }

    #[Test]
    #[Depends('create')]
    public function countOfTypeNone(Name $name)
    {
        static::assertSame(0, $name->countOfType('cn'));
    }

    #[Test]
    #[Depends('create')]
    public function iterable(Name $name)
    {
        $values = [];
        foreach ($name as $rdn) {
            $values[] = $rdn;
        }
        static::assertContainsOnlyInstancesOf(RDN::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function string(Name $name)
    {
        static::assertSame('name=one,name=two', $name->toString());
    }

    #[Test]
    #[Depends('create')]
    public function toStringMethod(Name $name)
    {
        static::assertIsString(strval($name));
    }
}
