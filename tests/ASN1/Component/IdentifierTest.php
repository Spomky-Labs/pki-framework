<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Component;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;

/**
 * @internal
 */
final class IdentifierTest extends TestCase
{
    /**
     * @test
     */
    public function classToName()
    {
        $name = Identifier::classToName(Identifier::CLASS_UNIVERSAL);
        static::assertEquals('UNIVERSAL', $name);
    }

    /**
     * @test
     */
    public function unknownClassToName()
    {
        $name = Identifier::classToName(0xff);
        static::assertEquals('CLASS 255', $name);
    }
}
