<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\X501\StringPrep\StringPreparer;

/**
 * @internal
 */
final class StringPreparerTest extends TestCase
{
    #[Test]
    public function create(): StringPreparer
    {
        $preparer = StringPreparer::forStringType(Element::TYPE_UTF8_STRING);
        static::assertInstanceOf(StringPreparer::class, $preparer);
        return $preparer;
    }

    #[Test]
    #[Depends('create')]
    public function withCaseFolding(StringPreparer $preparer): StringPreparer
    {
        $preparer = $preparer->withCaseFolding(true);
        static::assertInstanceOf(StringPreparer::class, $preparer);
        return $preparer;
    }

    #[Test]
    #[Depends('withCaseFolding')]
    public function prepare(StringPreparer $preparer)
    {
        $str = $preparer->prepare('TEST');
        static::assertSame(' test ', $str);
    }
}
