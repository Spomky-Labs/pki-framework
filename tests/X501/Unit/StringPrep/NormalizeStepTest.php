<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use Normalizer;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\StringPrep\NormalizeStep;

/**
 * @internal
 */
final class NormalizeStepTest extends TestCase
{
    /**
     * @test
     */
    public function apply()
    {
        $source = 'ฉันกินกระจกได้ แต่มันไม่ทำให้ฉันเจ็บ';
        $step = new NormalizeStep();
        $expected = normalizer_normalize($source, Normalizer::FORM_KC);
        static::assertEquals($expected, $step->apply($source));
    }
}
