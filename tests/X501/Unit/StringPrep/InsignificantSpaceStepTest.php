<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\StringPrep\InsignificantNonSubstringSpaceStep;

/**
 * @internal
 */
final class InsignificantSpaceStepTest extends TestCase
{
    /**
     * @dataProvider provideApplyNonSubstring
     *
     * @param string $string
     * @param string $expected
     *
     * @test
     */
    public function applyNonSubstring($string, $expected)
    {
        $step = new InsignificantNonSubstringSpaceStep();
        static::assertEquals($expected, $step->apply($string));
    }

    public function provideApplyNonSubstring(): iterable
    {
        static $nb_space = "\xc2\xa0";
        static $en_space = "\xe2\x80\x82";
        static $em_space = "\xe2\x80\x83";
        yield ['', '  '];
        yield [' ', '  '];
        yield ["{$nb_space}{$en_space}{$em_space}", '  '];
        yield ['abc', ' abc '];
        yield ['  abc   ', ' abc '];
        yield ['a bc', ' a  bc '];
        yield ["a{$nb_space}{$en_space}{$em_space}bc", ' a  bc '];
    }
}
