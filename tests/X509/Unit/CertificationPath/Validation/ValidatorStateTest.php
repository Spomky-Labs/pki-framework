<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\CertificationPath\Validation;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;
use Sop\X509\CertificationPath\PathValidation\ValidatorState;

/**
 * @internal
 */
final class ValidatorStateTest extends TestCase
{
    private static $_ca;

    public static function setUpBeforeClass(): void
    {
        self::$_ca = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_ca = null;
    }

    /**
     * @test
     */
    public function initialize()
    {
        $state = ValidatorState::initialize(PathValidationConfig::defaultConfig(), self::$_ca, 3);
        $this->assertInstanceOf(ValidatorState::class, $state);
        return $state;
    }

    /**
     * @depends initialize
     *
     * @test
     */
    public function validPolicyTreeFail(ValidatorState $state)
    {
        $this->expectException(LogicException::class);
        $state->withoutValidPolicyTree()
            ->validPolicyTree();
    }

    /**
     * @depends initialize
     *
     * @test
     */
    public function workingPublicKeyParameters(ValidatorState $state)
    {
        $this->assertInstanceOf(NullType::class, $state->workingPublicKeyParameters());
    }
}
