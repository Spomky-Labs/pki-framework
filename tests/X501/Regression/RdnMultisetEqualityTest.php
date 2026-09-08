<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Regression;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\RDN;

/**
 * An RDN is a SET, so two of them are equal when their attributes match as a multiset.
 *
 * Both sides used to be DER-sorted and then compared position by position under a case-insensitive rule, so a
 * case difference alone reordered the sort and two equal RDNs were reported as different.
 *
 * @internal
 */
final class RdnMultisetEqualityTest extends TestCase
{
    #[Test]
    public function aCaseDifferenceDoesNotReorderTheComparison(): void
    {
        // RFC 5280 sect. 7.1 makes these two equal.
        $a = RDN::fromAttributeValues(CommonNameValue::create('a'), CommonNameValue::create('B'));
        $b = RDN::fromAttributeValues(CommonNameValue::create('A'), CommonNameValue::create('b'));

        static::assertTrue($a->equals($b));
        static::assertTrue($b->equals($a));
    }

    #[Test]
    public function theOrderOfTheAttributesDoesNotMatter(): void
    {
        $a = RDN::fromAttributeValues(CommonNameValue::create('a'), CommonNameValue::create('b'));
        $b = RDN::fromAttributeValues(CommonNameValue::create('B'), CommonNameValue::create('A'));

        static::assertTrue($a->equals($b));
        static::assertTrue($b->equals($a));
    }

    #[Test]
    public function differentAttributesAreStillDifferent(): void
    {
        $a = RDN::fromAttributeValues(CommonNameValue::create('a'), CommonNameValue::create('b'));
        $b = RDN::fromAttributeValues(CommonNameValue::create('a'), CommonNameValue::create('c'));

        static::assertFalse($a->equals($b));
        static::assertFalse($b->equals($a));
    }

    #[Test]
    public function aRepeatedValueIsNotMatchedTwice(): void
    {
        $a = RDN::fromAttributeValues(CommonNameValue::create('a'), CommonNameValue::create('a'));
        $b = RDN::fromAttributeValues(CommonNameValue::create('a'), CommonNameValue::create('b'));

        static::assertFalse($a->equals($b));
        static::assertFalse($b->equals($a));
    }
}
