<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Tagged\ExplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetGroup;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class TargetGroupTest extends TestCase
{
    final public const URI = 'urn:test';

    /**
     * @test
     */
    public function create()
    {
        $target = new TargetGroup(new UniformResourceIdentifier(self::URI));
        $this->assertInstanceOf(TargetGroup::class, $target);
        return $target;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Target $target)
    {
        $el = $target->toASN1();
        $this->assertInstanceOf(ExplicitTagging::class, $el);
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
        $target = TargetGroup::fromASN1(TaggedType::fromDER($data));
        $this->assertInstanceOf(TargetGroup::class, $target);
        return $target;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Target $ref, Target $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function type(Target $target)
    {
        $this->assertEquals(Target::TYPE_GROUP, $target->type());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(TargetGroup $target)
    {
        $name = $target->name();
        $this->assertInstanceOf(GeneralName::class, $name);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(TargetGroup $target)
    {
        $this->assertIsString($target->string());
    }
}
