<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\X501\StringPrep\TranscodeStep;

/**
 * @internal
 */
final class TranscodeStepTest extends TestCase
{
    public function testUTF8()
    {
        static $str = 'κόσμε';
        $step = new TranscodeStep(Element::TYPE_UTF8_STRING);
        $this->assertEquals($str, $step->apply($str));
    }

    public function testPrintableString()
    {
        static $str = 'ASCII';
        $step = new TranscodeStep(Element::TYPE_PRINTABLE_STRING);
        $this->assertEquals($str, $step->apply($str));
    }

    public function testBMP()
    {
        static $str = 'κόσμε';
        $step = new TranscodeStep(Element::TYPE_BMP_STRING);
        $this->assertEquals($str, $step->apply(mb_convert_encoding($str, 'UCS-2BE', 'UTF-8')));
    }

    public function testUniversal()
    {
        static $str = 'κόσμε';
        $step = new TranscodeStep(Element::TYPE_UNIVERSAL_STRING);
        $this->assertEquals($str, $step->apply(mb_convert_encoding($str, 'UCS-4BE', 'UTF-8')));
    }

    public function testTeletex()
    {
        static $str = 'TEST';
        $step = new TranscodeStep(Element::TYPE_T61_STRING);
        $this->assertIsString($step->apply($str));
    }

    public function testInvalidType()
    {
        $step = new TranscodeStep(Element::TYPE_BOOLEAN);
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Unsupported string type BOOLEAN');
        $step->apply('TEST');
    }
}
