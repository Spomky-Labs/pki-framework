<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\X501\StringPrep\TranscodeStep;

/**
 * @internal
 */
final class TranscodeStepTest extends TestCase
{
    #[Test]
    public function uTF8()
    {
        static $str = 'κόσμε';
        $step = TranscodeStep::create(Element::TYPE_UTF8_STRING);
        static::assertEquals($str, $step->apply($str));
    }

    #[Test]
    public function printableString()
    {
        static $str = 'ASCII';
        $step = TranscodeStep::create(Element::TYPE_PRINTABLE_STRING);
        static::assertEquals($str, $step->apply($str));
    }

    #[Test]
    public function bMP()
    {
        static $str = 'κόσμε';
        $step = TranscodeStep::create(Element::TYPE_BMP_STRING);
        static::assertEquals($str, $step->apply(mb_convert_encoding((string) $str, 'UCS-2BE', 'UTF-8')));
    }

    #[Test]
    public function universal()
    {
        static $str = 'κόσμε';
        $step = TranscodeStep::create(Element::TYPE_UNIVERSAL_STRING);
        static::assertEquals($str, $step->apply(mb_convert_encoding((string) $str, 'UCS-4BE', 'UTF-8')));
    }

    #[Test]
    public function teletex()
    {
        static $str = 'TEST';
        $step = TranscodeStep::create(Element::TYPE_T61_STRING);
        static::assertIsString($step->apply($str));
    }

    #[Test]
    public function invalidType()
    {
        $step = TranscodeStep::create(Element::TYPE_BOOLEAN);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Unsupported string type BOOLEAN');
        $step->apply('TEST');
    }
}
