<?php

declare(strict_types=1);

namespace unit\general-name;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\X400Address;

/**
 * @group general-name
 *
 * @internal
 */
class X400AddressTest extends TestCase
{
    public function testCreate()
    {
        $name = X400Address::fromASN1(
            new ImplicitlyTaggedType(GeneralName::TAG_X400_ADDRESS,
                new Sequence()));
        $this->assertInstanceOf(X400Address::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
     *
     * @param X400Address $name
     */
    public function testEncode(X400Address $name)
    {
        $el = $name->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testChoiceTag($der)
    {
        $el = TaggedType::fromDER($der);
        $this->assertEquals(GeneralName::TAG_X400_ADDRESS, $el->tag());
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $name = X400Address::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(X400Address::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param X400Address $ref
     * @param X400Address $new
     */
    public function testRecoded(X400Address $ref, X400Address $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param X400Address $name
     */
    public function testString(X400Address $name)
    {
        $this->assertIsString($name->string());
    }
}
