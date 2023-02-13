<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ContextSpecificType;

/**
 * @internal
 */
final class ContextSpecificTypeTest extends TestCase
{
    #[Test]
    public function explicitType()
    {
        $el = Element::fromDER(hex2bin('a1020500'));
        static::assertInstanceOf(ContextSpecificType::class, $el);
    }

    #[Test]
    public function implicitType()
    {
        $el = Element::fromDER(hex2bin('8100'));
        static::assertInstanceOf(ContextSpecificType::class, $el);
    }
}
