<?php

declare(strict_types=1);

namespace Sop\Test\CryptoEncoding\Unit;

use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;
use UnexpectedValueException;

/**
 * @internal
 */
final class PEMBundleTest extends TestCase
{
    /**
     * @return PEMBundle
     *
     * @test
     */
    public function bundle()
    {
        $bundle = PEMBundle::fromFile(TEST_ASSETS_DIR . '/cacert.pem');
        $this->assertInstanceOf(PEMBundle::class, $bundle);
        return $bundle;
    }

    /**
     * @depends bundle
     *
     * @test
     */
    public function all(PEMBundle $bundle)
    {
        $this->assertContainsOnlyInstancesOf(PEM::class, $bundle->all());
    }

    /**
     * @depends bundle
     *
     * @test
     */
    public function first(PEMBundle $bundle)
    {
        $this->assertInstanceOf(PEM::class, $bundle->first());
        $this->assertEquals($bundle->all()[0], $bundle->first());
    }

    /**
     * @depends bundle
     *
     * @test
     */
    public function last(PEMBundle $bundle)
    {
        $this->assertInstanceOf(PEM::class, $bundle->last());
        $this->assertEquals($bundle->all()[149], $bundle->last());
    }

    /**
     * @depends bundle
     *
     * @test
     */
    public function countMethod(PEMBundle $bundle)
    {
        $this->assertCount(150, $bundle);
    }

    /**
     * @depends bundle
     *
     * @test
     */
    public function iterator(PEMBundle $bundle)
    {
        $values = [];
        foreach ($bundle as $pem) {
            $values[] = $pem;
        }
        $this->assertContainsOnlyInstancesOf(PEM::class, $values);
    }

    /**
     * @depends bundle
     *
     * @test
     */
    public function string(PEMBundle $bundle)
    {
        $this->assertIsString($bundle->string());
    }

    /**
     * @depends bundle
     *
     * @test
     */
    public function toStringMethod(PEMBundle $bundle)
    {
        $this->assertIsString(strval($bundle));
    }

    /**
     * @test
     */
    public function invalidPEM()
    {
        $this->expectException(UnexpectedValueException::class);
        PEMBundle::fromString('invalid');
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
        PEMBundle::fromString($str);
    }

    /**
     * @test
     */
    public function invalidFile()
    {
        $this->expectException(RuntimeException::class);
        PEMBundle::fromFile(TEST_ASSETS_DIR . '/nonexistent');
    }

    /**
     * @test
     */
    public function firstEmptyFail()
    {
        $bundle = new PEMBundle();
        $this->expectException(LogicException::class);
        $bundle->first();
    }

    /**
     * @test
     */
    public function lastEmptyFail()
    {
        $bundle = new PEMBundle();
        $this->expectException(LogicException::class);
        $bundle->last();
    }

    /**
     * @depends bundle
     *
     * @test
     */
    public function withPEMs(PEMBundle $bundle)
    {
        $bundle = $bundle->withPEMs(new PEM('TEST', 'data'));
        $this->assertCount(151, $bundle);
    }
}
