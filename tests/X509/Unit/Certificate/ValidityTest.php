<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Validity;

/**
 * @internal
 */
final class ValidityTest extends TestCase
{
    final public const NB = '2016-04-06 12:00:00';

    final public const NA = '2016-04-06 13:00:00';

    /**
     * @test
     */
    public function create()
    {
        $validity = Validity::fromStrings(self::NB, self::NA);
        $this->assertInstanceOf(Validity::class, $validity);
        return $validity;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Validity $validity)
    {
        $seq = $validity->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $validity = Validity::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(Validity::class, $validity);
        return $validity;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Validity $ref, Validity $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function notBefore(Validity $validity)
    {
        $this->assertEquals(new DateTimeImmutable(self::NB), $validity->notBefore() ->dateTime());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function notAfter(Validity $validity)
    {
        $this->assertEquals(new DateTimeImmutable(self::NA), $validity->notAfter() ->dateTime());
    }
}
