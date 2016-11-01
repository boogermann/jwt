<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Storage\Builder;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class ConfigurationTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Parser|\PHPUnit_Framework_MockObject_MockObject
     */
    private $parser;

    /**
     * @var Signer|\PHPUnit_Framework_MockObject_MockObject
     */
    private $signer;

    /**
     * @var Parsing\Encoder|\PHPUnit_Framework_MockObject_MockObject
     */
    private $encoder;

    /**
     * @var Parsing\Decoder|\PHPUnit_Framework_MockObject_MockObject
     */
    private $decoder;

    /**
     * @var Validator|\PHPUnit_Framework_MockObject_MockObject
     */
    private $validator;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->signer = $this->createMock(Signer::class);
        $this->encoder = $this->createMock(Parsing\Encoder::class);
        $this->decoder = $this->createMock(Parsing\Decoder::class);
        $this->parser = $this->createMock(Parser::class);
        $this->validator = $this->createMock(Validator::class);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::createBuilder
     * @covers \Lcobucci\JWT\Configuration::getEncoder
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     */
    public function createBuilderShouldCreateABuilderWithDefaultEncoderAndClaimFactory()
    {
        $config = new Configuration();
        $builder = $config->createBuilder();

        self::assertInstanceOf(Builder::class, $builder);
        self::assertAttributeNotSame($this->encoder, 'encoder', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::createBuilder
     * @covers \Lcobucci\JWT\Configuration::setEncoder
     * @covers \Lcobucci\JWT\Configuration::getEncoder
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     */
    public function createBuilderShouldCreateABuilderWithCustomizedEncoderAndClaimFactory()
    {
        $config = new Configuration();
        $config->setEncoder($this->encoder);

        $builder = $config->createBuilder();

        self::assertInstanceOf(Builder::class, $builder);
        self::assertAttributeSame($this->encoder, 'encoder', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::getDecoder
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     */
    public function getParserShouldReturnAParserWithDefaultDecoder()
    {
        $config = new Configuration();
        $parser = $config->getParser();

        self::assertInstanceOf(Parser::class, $parser);
        self::assertAttributeNotSame($this->decoder, 'decoder', $parser);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::setDecoder
     * @covers \Lcobucci\JWT\Configuration::getDecoder
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     */
    public function getParserShouldReturnAParserWithCustomizedDecoderAndClaimFactory()
    {
        $config = new Configuration();
        $config->setDecoder($this->decoder);

        $parser = $config->getParser();

        self::assertInstanceOf(Parser::class, $parser);
        self::assertAttributeSame($this->decoder, 'decoder', $parser);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::setParser
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     */
    public function getParserShouldNotCreateAnInstanceIfItWasConfigured()
    {
        $config = new Configuration();
        $config->setParser($this->parser);

        self::assertSame($this->parser, $config->getParser());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getSigner
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     * @uses \Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function getSignerShouldReturnTheDefaultWhenItWasNotConfigured()
    {
        $config = new Configuration();

        self::assertInstanceOf(Sha256::class, $config->getSigner());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getSigner
     * @covers \Lcobucci\JWT\Configuration::setSigner
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     */
    public function getSignerShouldReturnTheConfiguredSigner()
    {
        $config = new Configuration();
        $config->setSigner($this->signer);

        self::assertSame($this->signer, $config->getSigner());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getValidator
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     */
    public function getValidatorShouldReturnTheDefaultWhenItWasNotConfigured()
    {
        $config = new Configuration();
        $validator = $config->getValidator();

        self::assertNotSame($this->validator, $validator);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getValidator
     * @covers \Lcobucci\JWT\Configuration::setValidator
     *
     * @uses \Lcobucci\JWT\Storage\Builder
     * @uses \Lcobucci\JWT\Storage\Parser
     */
    public function getValidatorShouldReturnTheConfiguredValidator()
    {
        $config = new Configuration();
        $config->setValidator($this->validator);

        self::assertSame($this->validator, $config->getValidator());
    }
}
