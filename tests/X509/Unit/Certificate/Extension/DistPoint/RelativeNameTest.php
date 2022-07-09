<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X501\ASN1\AttributeTypeAndValue;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\RDN;
use Sop\X509\Certificate\Extension\DistributionPoint\RelativeName;

/**
 * @internal
 */
final class RelativeNameTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $name = new RelativeName(new RDN(AttributeTypeAndValue::fromAttributeValue(new CommonNameValue('Test'))));
        $this->assertInstanceOf(RelativeName::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(RelativeName $name)
    {
        $el = $name->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $name = RelativeName::fromTaggedType(TaggedType::fromDER($data));
        $this->assertInstanceOf(RelativeName::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(RelativeName $ref, RelativeName $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function rDN(RelativeName $name)
    {
        $rdn = $name->rdn();
        $this->assertInstanceOf(RDN::class, $rdn);
    }
}
