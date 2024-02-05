<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoEncoding\Unit;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class PEMTest extends TestCase
{
    #[Test]
    public function fromString()
    {
        $str = file_get_contents(TEST_ASSETS_DIR . '/public_key.pem');
        $pem = PEM::fromString($str);
        static::assertInstanceOf(PEM::class, $pem);
    }

    #[Test]
    public function fromFile(): PEM
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/public_key.pem');
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('fromFile')]
    public function type(PEM $pem)
    {
        static::assertSame(PEM::TYPE_PUBLIC_KEY, $pem->type());
    }

    #[Test]
    public function data()
    {
        $data = 'payload';
        $encoded = base64_encode($data);
        $str = <<<CODE_SAMPLE
-----BEGIN TEST-----
{$encoded}
-----END TEST-----
CODE_SAMPLE;
        static::assertSame($data, PEM::fromString($str)->data());
    }

    #[Test]
    public function invalidPEM()
    {
        $this->expectException(UnexpectedValueException::class);
        PEM::fromString('invalid');
    }

    #[Test]
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

    #[Test]
    public function invalidFile()
    {
        $this->expectException(RuntimeException::class);
        PEM::fromFile(TEST_ASSETS_DIR . '/nonexistent');
    }

    #[Test]
    #[Depends('fromFile')]
    public function string(PEM $pem)
    {
        static::assertIsString($pem->string());
    }

    #[Test]
    #[Depends('fromFile')]
    public function toStringMethod(PEM $pem)
    {
        static::assertIsString(strval($pem));
    }
}
