<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\X501\StringPrep\StringPreparer;

/**
 * @internal
 */
final class StringPreparerTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $preparer = StringPreparer::forStringType(Element::TYPE_UTF8_STRING);
        static::assertInstanceOf(StringPreparer::class, $preparer);
        return $preparer;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withCaseFolding(StringPreparer $preparer)
    {
        $preparer = $preparer->withCaseFolding(true);
        static::assertInstanceOf(StringPreparer::class, $preparer);
        return $preparer;
    }

    /**
     * @depends withCaseFolding
     *
     * @test
     */
    public function prepare(StringPreparer $preparer)
    {
        $str = $preparer->prepare('TEST');
        static::assertEquals(' test ', $str);
    }
}
