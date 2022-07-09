<?php

declare(strict_types=1);

namespace Sop\Test\CryptoEncoding\Unit;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;

/**
 * @internal
 */
final class PEMBundleTest extends TestCase
{
    /**
     * @return PEMBundle
     */
    public function testBundle()
    {
        $bundle = PEMBundle::fromFile(TEST_ASSETS_DIR . '/cacert.pem');
        $this->assertInstanceOf(PEMBundle::class, $bundle);
        return $bundle;
    }

    /**
     * @depends testBundle
     */
    public function testAll(PEMBundle $bundle)
    {
        $this->assertContainsOnlyInstancesOf(PEM::class, $bundle->all());
    }

    /**
     * @depends testBundle
     */
    public function testFirst(PEMBundle $bundle)
    {
        $this->assertInstanceOf(PEM::class, $bundle->first());
        $this->assertEquals($bundle->all()[0], $bundle->first());
    }

    /**
     * @depends testBundle
     */
    public function testLast(PEMBundle $bundle)
    {
        $this->assertInstanceOf(PEM::class, $bundle->last());
        $this->assertEquals($bundle->all()[149], $bundle->last());
    }

    /**
     * @depends testBundle
     */
    public function testCount(PEMBundle $bundle)
    {
        $this->assertCount(150, $bundle);
    }

    /**
     * @depends testBundle
     */
    public function testIterator(PEMBundle $bundle)
    {
        $values = [];
        foreach ($bundle as $pem) {
            $values[] = $pem;
        }
        $this->assertContainsOnlyInstancesOf(PEM::class, $values);
    }

    /**
     * @depends testBundle
     */
    public function testString(PEMBundle $bundle)
    {
        $this->assertIsString($bundle->string());
    }

    /**
     * @depends testBundle
     */
    public function testToString(PEMBundle $bundle)
    {
        $this->assertIsString(strval($bundle));
    }

    public function testInvalidPEM()
    {
        $this->expectException(\UnexpectedValueException::class);
        PEMBundle::fromString('invalid');
    }

    public function testInvalidPEMData()
    {
        $str = <<<'CODE_SAMPLE'
-----BEGIN TEST-----
%%%
-----END TEST-----
CODE_SAMPLE;
        $this->expectException(\UnexpectedValueException::class);
        PEMBundle::fromString($str);
    }

    public function testInvalidFile()
    {
        $this->expectException(\RuntimeException::class);
        PEMBundle::fromFile(TEST_ASSETS_DIR . '/nonexistent');
    }

    public function testFirstEmptyFail()
    {
        $bundle = new PEMBundle();
        $this->expectException(\LogicException::class);
        $bundle->first();
    }

    public function testLastEmptyFail()
    {
        $bundle = new PEMBundle();
        $this->expectException(\LogicException::class);
        $bundle->last();
    }

    /**
     * @depends testBundle
     */
    public function testWithPEMs(PEMBundle $bundle)
    {
        $bundle = $bundle->withPEMs(new PEM('TEST', 'data'));
        $this->assertCount(151, $bundle);
    }
}
