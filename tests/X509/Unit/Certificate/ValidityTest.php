<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * @internal
 */
final class ValidityTest extends TestCase
{
    final public const NB = '2016-04-06 12:00:00';

    final public const NA = '2016-04-06 13:00:00';

    #[Test]
    public function create(): Validity
    {
        $validity = Validity::fromStrings(self::NB, self::NA);
        static::assertInstanceOf(Validity::class, $validity);
        return $validity;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Validity $validity): string
    {
        $seq = $validity->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): Validity
    {
        $validity = Validity::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Validity::class, $validity);
        return $validity;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Validity $ref, Validity $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function notBefore(Validity $validity)
    {
        static::assertEquals(new DateTimeImmutable(self::NB), $validity->notBefore()->dateTime());
    }

    #[Test]
    #[Depends('create')]
    public function notAfter(Validity $validity)
    {
        static::assertEquals(new DateTimeImmutable(self::NA), $validity->notAfter()->dateTime());
    }
}
