<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1\Collection;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\DescriptionValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;
use SpomkyLabs\Pki\X501\ASN1\Collection\SetOfAttributes;

/**
 * @internal
 */
final class SetOfAttributesTest extends TestCase
{
    #[Test]
    public function create(): SetOfAttributes
    {
        $c = SetOfAttributes::fromAttributeValues(NameValue::create('n'), DescriptionValue::create('d'));
        static::assertInstanceOf(SetOfAttributes::class, $c);
        return $c;
    }

    #[Test]
    #[Depends('create')]
    public function encode(SetOfAttributes $c): Set
    {
        $el = $c->toASN1();
        static::assertInstanceOf(Set::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Set $set): SetOfAttributes
    {
        $c = SetOfAttributes::fromASN1($set);
        static::assertInstanceOf(SetOfAttributes::class, $c);
        return $c;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(SetOfAttributes $original, SetOfAttributes $recoded)
    {
        // compare DER encodings because SET OF sorts the elements
        static::assertSame($original->toASN1()->toDER(), $recoded->toASN1()->toDER());
    }
}
