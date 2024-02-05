<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\StringPrep\InsignificantNonSubstringSpaceStep;

/**
 * @internal
 */
final class InsignificantSpaceStepTest extends TestCase
{
    /**
     * @param string $string
     * @param string $expected
     */
    #[Test]
    #[DataProvider('provideApplyNonSubstring')]
    public function applyNonSubstring($string, $expected)
    {
        $step = new InsignificantNonSubstringSpaceStep();
        static::assertSame($expected, $step->apply($string));
    }

    public static function provideApplyNonSubstring(): iterable
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
