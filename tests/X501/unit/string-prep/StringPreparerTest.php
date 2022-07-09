<?php

declare(strict_types=1);

namespace unit\string-prep;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\X501\StringPrep\StringPreparer;

/**
 * @group string-prep
 *
 * @internal
 */
class StringPreparerTest extends TestCase
{
    public function testCreate()
    {
        $preparer = StringPreparer::forStringType(Element::TYPE_UTF8_STRING);
        $this->assertInstanceOf(StringPreparer::class, $preparer);
        return $preparer;
    }

    /**
     * @depends testCreate
     *
     * @param StringPreparer $preparer
     */
    public function testWithCaseFolding(StringPreparer $preparer)
    {
        $preparer = $preparer->withCaseFolding(true);
        $this->assertInstanceOf(StringPreparer::class, $preparer);
        return $preparer;
    }

    /**
     * @depends testWithCaseFolding
     *
     * @param StringPreparer $preparer
     */
    public function testPrepare(StringPreparer $preparer)
    {
        $str = $preparer->prepare('TEST');
        $this->assertEquals(' test ', $str);
    }
}
