<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Encryption;

use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Encryption\PKCS7Padding;

/**
 * @internal
 */
final class PKCS7PaddingTest extends TestCase
{
    /**
     * @return iterable<string, array{string, int, string}>
     */
    public static function padded(): iterable
    {
        yield 'empty' => ['', 8, str_repeat("\x08", 8)];
        yield 'one byte short' => ['1234567', 8, "1234567\x01"];
        yield 'a full block' => ['12345678', 8, '12345678' . str_repeat("\x08", 8)];
        yield 'two bytes short of 16' => ['0123456789abcd', 16, "0123456789abcd\x02\x02"];
        yield 'block size 1' => ['ab', 1, "ab\x01"];
        yield 'block size 255' => ['a', 255, 'a' . str_repeat("\xFE", 254)];
    }

    #[Test]
    #[DataProvider('padded')]
    public function add(string $data, int $blockSize, string $expected): void
    {
        static::assertSame($expected, PKCS7Padding::add($data, $blockSize));
    }

    #[Test]
    #[DataProvider('padded')]
    public function remove(string $expected, int $blockSize, string $data): void
    {
        static::assertSame($expected, PKCS7Padding::remove($data, $blockSize));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function invalid(): iterable
    {
        yield 'empty' => ['', 8];
        yield 'not a multiple of the block size' => ["1234567\x01\x01", 8];
        yield 'padding byte 0' => ["1234567\x00", 8];
        yield 'padding longer than the block' => [str_repeat("\x09", 16), 8];
        yield 'padding 17 with block size 16' => [str_repeat("\x11", 32), 16];
        yield 'second byte wrong' => ["123456\x01\x02", 8];
        yield 'first padding byte wrong' => ["12345\x04\x03\x03", 8];
        yield 'last byte of a full padding block wrong' => ["\x07" . str_repeat("\x08", 7), 8];
        yield 'middle byte of a full padding block wrong' => [str_repeat("\x10", 8) . "\x00" . str_repeat("\x10", 7), 16];
        yield 'last of 16 padding bytes differs by one bit' => ["\x00" . str_repeat("\x10", 14) . "\x10", 16];
        yield 'block size 0' => ['a', 0];
        yield 'block size 256' => [str_repeat("\x01", 256), 256];
    }

    #[Test]
    #[DataProvider('invalid')]
    public function invalidPaddingIsRefused(string $data, int $blockSize): void
    {
        static::assertNull(PKCS7Padding::remove($data, $blockSize));
    }

    #[Test]
    public function onlyTheLastBlockIsInspected(): void
    {
        // bytes before the padding that look like padding must survive
        static::assertSame("\x02\x02\x02\x02\x02\x02\x02", PKCS7Padding::remove(str_repeat("\x02", 7) . "\x01", 8));
        static::assertSame(
            str_repeat("\x08", 8) . 'abc',
            PKCS7Padding::remove(str_repeat("\x08", 8) . "abc\x05\x05\x05\x05\x05", 8)
        );
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function invalidBlockSizes(): iterable
    {
        yield '0' => [0];
        yield '256' => [256];
    }

    #[Test]
    #[DataProvider('invalidBlockSizes')]
    public function addRefusesInvalidBlockSize(int $blockSize): void
    {
        $this->expectException(LogicException::class);
        PKCS7Padding::add('a', $blockSize);
    }

    #[Test]
    public function addAcceptsTheBoundaryBlockSizes(): void
    {
        static::assertSame("a\x01", PKCS7Padding::add('a', 1));
        static::assertSame(255, mb_strlen(PKCS7Padding::add('', 255), '8bit'));
        static::assertSame('', PKCS7Padding::remove(str_repeat("\x01", 1), 1));
    }
}
