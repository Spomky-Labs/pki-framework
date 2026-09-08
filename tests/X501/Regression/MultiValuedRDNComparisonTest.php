<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Regression;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeTypeAndValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X501\ASN1\RDN;

/**
 * An RDN is a SET, so two of them are equal when their attributes match as a multiset. Pairing the two sides off one
 * at a time answers that correctly but costs a comparison for every pair, and each comparison prepares a string
 * afresh. A multi-valued RDN is entirely attacker-chosen in a certificate subject, so writing the attributes in the
 * reverse order made the inner scan run to the end every time: a 35 KB subject cost 20 seconds per comparison, and
 * the cost grew quadratically.
 *
 * Name::equals() sits on the certification path, once per path element in checkIssuer(), once per candidate per node
 * in the path builder, and again in CertificateBundle::contains().
 *
 * @internal
 */
final class MultiValuedRDNComparisonTest extends TestCase
{
    #[Test]
    public function theReverseOrderCostsNoMoreThanTheSameOrder(): void
    {
        $values = [];
        for ($i = 0; $i < 2000; ++$i) {
            $values[] = 'value' . $i;
        }
        $left = Name::create(self::rdn(...$values));
        $reversed = Name::create(self::rdn(...array_reverse($values)));

        $started = microtime(true);
        static::assertTrue($left->equals($reversed));
        $elapsed = microtime(true) - $started;

        // pairing the two sides off one at a time took about twenty seconds here
        static::assertLessThan(2.0, $elapsed);
    }

    #[Test]
    public function comparingALargeMultiValuedRDNIsLinear(): void
    {
        $small = self::elapsed(500);
        $large = self::elapsed(4000);

        static::assertLessThan(1.0, $large);
        static::assertLessThan(max($small, 0.001) * 40, $large);
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, bool}>
     */
    public static function multiValuedRDNs(): iterable
    {
        yield 'same values, same order' => [['a', 'b', 'c'], ['a', 'b', 'c'], true];
        yield 'same values, different order' => [['a', 'b', 'c'], ['c', 'a', 'b'], true];
        yield 'same values, reversed' => [['a', 'b', 'c'], ['c', 'b', 'a'], true];
        yield 'one value differs' => [['a', 'b', 'c'], ['a', 'b', 'd'], false];
        yield 'a repeated value on one side only' => [['a', 'a', 'b'], ['a', 'b', 'b'], false];
        yield 'the same value repeated' => [['a', 'a'], ['a', 'a'], true];
        yield 'case is ignored, order is not significant' => [['a', 'B'], ['A', 'b'], true];
        yield 'a single value' => [['a'], ['a'], true];
        yield 'a single value that differs' => [['a'], ['b'], false];
    }

    /**
     * @param list<string> $left
     * @param list<string> $right
     */
    #[Test]
    #[DataProvider('multiValuedRDNs')]
    public function theMultisetSemanticsAreUnchanged(array $left, array $right, bool $expected): void
    {
        static::assertSame($expected, self::rdn(...$left)->equals(self::rdn(...$right)));
        static::assertSame($expected, self::rdn(...$right)->equals(self::rdn(...$left)));
    }

    #[Test]
    public function attributeCountStillDecidesFirst(): void
    {
        static::assertFalse(self::rdn('a', 'b')->equals(self::rdn('a')));
    }

    private static function elapsed(int $attributes): float
    {
        $values = [];
        for ($i = 0; $i < $attributes; ++$i) {
            $values[] = 'value' . $i;
        }
        $left = Name::create(self::rdn(...$values));
        $right = Name::create(self::rdn(...$values));

        $started = microtime(true);
        static::assertTrue($left->equals($right));

        return microtime(true) - $started;
    }

    private static function rdn(string ...$values): RDN
    {
        $attributes = [];
        foreach ($values as $value) {
            $attributes[] = AttributeTypeAndValue::create(
                AttributeType::create(AttributeType::OID_COMMON_NAME),
                AttributeValue::fromASN1ByOID(
                    AttributeType::OID_COMMON_NAME,
                    UTF8String::create($value)->asUnspecified()
                )
            );
        }

        return RDN::create(...$attributes);
    }
}
