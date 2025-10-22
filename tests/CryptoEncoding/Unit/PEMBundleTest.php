<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoEncoding\Unit;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoEncoding\PEMBundle;
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class PEMBundleTest extends TestCase
{
    #[Test]
    public function bundle(): PEMBundle
    {
        $bundle = PEMBundle::fromFile(TEST_ASSETS_DIR . '/cacert.pem');
        static::assertInstanceOf(PEMBundle::class, $bundle);
        return $bundle;
    }

    #[Test]
    #[Depends('bundle')]
    public function all(PEMBundle $bundle)
    {
        static::assertContainsOnlyInstancesOf(PEM::class, $bundle->all());
    }

    #[Test]
    #[Depends('bundle')]
    public function first(PEMBundle $bundle)
    {
        static::assertInstanceOf(PEM::class, $bundle->first());
        static::assertEquals($bundle->all()[0], $bundle->first());
    }

    #[Test]
    #[Depends('bundle')]
    public function last(PEMBundle $bundle)
    {
        static::assertInstanceOf(PEM::class, $bundle->last());
        static::assertEquals($bundle->all()[149], $bundle->last());
    }

    #[Test]
    #[Depends('bundle')]
    public function countMethod(PEMBundle $bundle)
    {
        static::assertCount(150, $bundle);
    }

    #[Test]
    #[Depends('bundle')]
    public function iterator(PEMBundle $bundle)
    {
        $values = [];
        foreach ($bundle as $pem) {
            $values[] = $pem;
        }
        static::assertContainsOnlyInstancesOf(PEM::class, $values);
    }

    #[Test]
    #[Depends('bundle')]
    public function string(PEMBundle $bundle)
    {
        static::assertIsString($bundle->string());
    }

    #[Test]
    #[Depends('bundle')]
    public function toStringMethod(PEMBundle $bundle)
    {
        static::assertIsString(strval($bundle));
    }

    #[Test]
    public function invalidPEM()
    {
        $this->expectException(UnexpectedValueException::class);
        PEMBundle::fromString('invalid');
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
        PEMBundle::fromString($str);
    }

    #[Test]
    public function invalidFile()
    {
        $this->expectException(RuntimeException::class);
        PEMBundle::fromFile(TEST_ASSETS_DIR . '/nonexistent');
    }

    #[Test]
    public function firstEmptyFail()
    {
        $bundle = PEMBundle::create();
        $this->expectException(LogicException::class);
        $bundle->first();
    }

    #[Test]
    public function lastEmptyFail()
    {
        $bundle = PEMBundle::create();
        $this->expectException(LogicException::class);
        $bundle->last();
    }

    #[Test]
    #[Depends('bundle')]
    public function withPEMs(PEMBundle $bundle)
    {
        $bundle = $bundle->withPEMs(PEM::create('TEST', 'data'));
        static::assertCount(151, $bundle);
    }
}
