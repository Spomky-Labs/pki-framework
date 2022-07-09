<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\StringPrep;

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
     */
    public function testWithCaseFolding(StringPreparer $preparer)
    {
        $preparer = $preparer->withCaseFolding(true);
        $this->assertInstanceOf(StringPreparer::class, $preparer);
        return $preparer;
    }

    /**
     * @depends testWithCaseFolding
     */
    public function testPrepare(StringPreparer $preparer)
    {
        $str = $preparer->prepare('TEST');
        $this->assertEquals(' test ', $str);
    }
}
