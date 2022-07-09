<?php

declare(strict_types=1);

namespace Sop\Test\CryptoEncoding\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\CryptoEncoding\PEM;
use UnexpectedValueException;

/**
 * @internal
 */
final class PEMTest extends TestCase
{
    public function testFromString()
    {
        $str = file_get_contents(TEST_ASSETS_DIR . '/public_key.pem');
        $pem = PEM::fromString($str);
        $this->assertInstanceOf(PEM::class, $pem);
    }

    public function testFromFile(): PEM
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/public_key.pem');
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testFromFile
     */
    public function testType(PEM $pem)
    {
        $this->assertEquals(PEM::TYPE_PUBLIC_KEY, $pem->type());
    }

    public function testData()
    {
        $data = 'payload';
        $encoded = base64_encode($data);
        $str = <<<CODE_SAMPLE
-----BEGIN TEST-----
{$encoded}
-----END TEST-----
CODE_SAMPLE;
        $this->assertEquals($data, PEM::fromString($str)->data());
    }

    public function testInvalidPEM()
    {
        $this->expectException(UnexpectedValueException::class);
        PEM::fromString('invalid');
    }

    public function testInvalidPEMData()
    {
        $str = <<<'CODE_SAMPLE'
-----BEGIN TEST-----
%%%
-----END TEST-----
CODE_SAMPLE;
        $this->expectException(UnexpectedValueException::class);
        PEM::fromString($str);
    }

    public function testInvalidFile()
    {
        $this->expectException(RuntimeException::class);
        PEM::fromFile(TEST_ASSETS_DIR . '/nonexistent');
    }

    /**
     * @depends testFromFile
     */
    public function testString(PEM $pem)
    {
        $this->assertIsString($pem->string());
    }

    /**
     * @depends testFromFile
     */
    public function testToString(PEM $pem)
    {
        $this->assertIsString(strval($pem));
    }
}
