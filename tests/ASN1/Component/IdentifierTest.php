<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Component;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Component\Identifier;

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
        $this->assertEquals('UNIVERSAL', $name);
    }

    /**
     * @test
     */
    public function unknownClassToName()
    {
        $name = Identifier::classToName(0xff);
        $this->assertEquals('CLASS 255', $name);
    }
}
