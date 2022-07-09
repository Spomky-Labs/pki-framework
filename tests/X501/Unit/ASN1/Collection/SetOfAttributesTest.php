<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1\Collection;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Set;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\Collection\SetOfAttributes;

/**
 * @internal
 */
final class SetOfAttributesTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $c = SetOfAttributes::fromAttributeValues(new NameValue('n'), new DescriptionValue('d'));
        $this->assertInstanceOf(SetOfAttributes::class, $c);
        return $c;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(SetOfAttributes $c)
    {
        $el = $c->toASN1();
        $this->assertInstanceOf(Set::class, $el);
        return $el;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(Set $set)
    {
        $c = SetOfAttributes::fromASN1($set);
        $this->assertInstanceOf(SetOfAttributes::class, $c);
        return $c;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(SetOfAttributes $original, SetOfAttributes $recoded)
    {
        // compare DER encodings because SET OF sorts the elements
        $this->assertEquals($original->toASN1()->toDER(), $recoded->toASN1()->toDER());
    }
}
