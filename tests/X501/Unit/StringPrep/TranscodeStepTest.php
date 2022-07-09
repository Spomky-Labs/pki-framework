<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\X501\StringPrep\TranscodeStep;

/**
 * @internal
 */
final class TranscodeStepTest extends TestCase
{
    /**
     * @test
     */
    public function uTF8()
    {
        static $str = 'κόσμε';
        $step = new TranscodeStep(Element::TYPE_UTF8_STRING);
        static::assertEquals($str, $step->apply($str));
    }

    /**
     * @test
     */
    public function printableString()
    {
        static $str = 'ASCII';
        $step = new TranscodeStep(Element::TYPE_PRINTABLE_STRING);
        static::assertEquals($str, $step->apply($str));
    }

    /**
     * @test
     */
    public function bMP()
    {
        static $str = 'κόσμε';
        $step = new TranscodeStep(Element::TYPE_BMP_STRING);
        static::assertEquals($str, $step->apply(mb_convert_encoding($str, 'UCS-2BE', 'UTF-8')));
    }

    /**
     * @test
     */
    public function universal()
    {
        static $str = 'κόσμε';
        $step = new TranscodeStep(Element::TYPE_UNIVERSAL_STRING);
        static::assertEquals($str, $step->apply(mb_convert_encoding($str, 'UCS-4BE', 'UTF-8')));
    }

    /**
     * @test
     */
    public function teletex()
    {
        static $str = 'TEST';
        $step = new TranscodeStep(Element::TYPE_T61_STRING);
        static::assertIsString($step->apply($str));
    }

    /**
     * @test
     */
    public function invalidType()
    {
        $step = new TranscodeStep(Element::TYPE_BOOLEAN);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Unsupported string type BOOLEAN');
        $step->apply('TEST');
    }
}
