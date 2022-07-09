<?php

declare(strict_types=1);

namespace Sop\Test\CryptoEncoding\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\CryptoEncoding\PEM;
use function strval;
use UnexpectedValueException;

/**
 * @internal
 */
final class PEMTest extends TestCase
{
    /**
     * @test
     */
    public function fromString()
    {
        $str = file_get_contents(TEST_ASSETS_DIR . '/public_key.pem');
        $pem = PEM::fromString($str);
        static::assertInstanceOf(PEM::class, $pem);
    }

    /**
     * @test
     */
    public function fromFile(): PEM
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/public_key.pem');
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends fromFile
     *
     * @test
     */
    public function type(PEM $pem)
    {
        static::assertEquals(PEM::TYPE_PUBLIC_KEY, $pem->type());
    }

    /**
     * @test
     */
    public function data()
    {
        $data = 'payload';
        $encoded = base64_encode($data);
        $str = <<<CODE_SAMPLE
-----BEGIN TEST-----
{$encoded}
-----END TEST-----
CODE_SAMPLE;
        static::assertEquals($data, PEM::fromString($str)->data());
    }

    /**
     * @test
     */
    public function invalidPEM()
    {
        $this->expectException(UnexpectedValueException::class);
        PEM::fromString('invalid');
    }

    /**
     * @test
     */
    public function invalidPEMData()
    {
        $str = <<<'CODE_SAMPLE'
-----BEGIN TEST-----
%%%
-----END TEST-----
CODE_SAMPLE;
        $this->expectException(UnexpectedValueException::class);
        PEM::fromString($str);
    }

    /**
     * @test
     */
    public function invalidFile()
    {
        $this->expectException(RuntimeException::class);
        PEM::fromFile(TEST_ASSETS_DIR . '/nonexistent');
    }

    /**
     * @depends fromFile
     *
     * @test
     */
    public function string(PEM $pem)
    {
        static::assertIsString($pem->string());
    }

    /**
     * @depends fromFile
     *
     * @test
     */
    public function toStringMethod(PEM $pem)
    {
        static::assertIsString(strval($pem));
    }
}
