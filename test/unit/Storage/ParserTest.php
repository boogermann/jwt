<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Storage;

use Lcobucci\Jose\Parsing\Decoder;
use RuntimeException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class ParserTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Decoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $decoder;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->decoder = $this->createMock(Decoder::class);
    }

    /**
     * @return Parser
     */
    private function createParser(): Parser
    {
        return new Parser($this->decoder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Storage\Parser::__construct
     */
    public function constructMustConfigureTheAttributes()
    {
        $parser = $this->createParser();

        self::assertAttributeSame($this->decoder, 'decoder', $parser);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Storage\Parser::parse
     * @covers \Lcobucci\JWT\Storage\Parser::splitJwt
     *
     * @expectedException \InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenJWSDoNotHaveThreeParts()
    {
        $parser = $this->createParser();
        $parser->parse('');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Storage\Parser::parse
     * @covers \Lcobucci\JWT\Storage\Parser::splitJwt
     * @covers \Lcobucci\JWT\Storage\Parser::parseHeader
     *
     * @expectedException \RuntimeException
     */
    public function parseMustRaiseExceptionWhenHeaderCannotBeDecoded()
    {
        $this->decoder->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('b');

        $this->decoder->method('jsonDecode')
                      ->with('b')
                      ->willThrowException(new RuntimeException());

        $parser = $this->createParser();
        $parser->parse('a.b.');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Storage\Parser::parse
     * @covers \Lcobucci\JWT\Storage\Parser::splitJwt
     * @covers \Lcobucci\JWT\Storage\Parser::parseHeader
     *
     * @expectedException \InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken()
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();
        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Parser::__construct
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Parser::parse
     * @covers \Lcobucci\JWT\Storage\Parser::createToken
     * @covers \Lcobucci\JWT\Storage\Parser::splitJwt
     * @covers \Lcobucci\JWT\Storage\Parser::parseHeader
     * @covers \Lcobucci\JWT\Storage\Parser::parseClaims
     * @covers \Lcobucci\JWT\Storage\Parser::parseSignature
     *
     */
    public function parseMustReturnAnUnsecuredTokenWhenSignatureIsNotInformed()
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims = new DataSet(['aud' => 'test'], 'b');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals(null, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Parser::__construct
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Parser::parse
     * @covers \Lcobucci\JWT\Storage\Parser::createToken
     * @covers \Lcobucci\JWT\Storage\Parser::splitJwt
     * @covers \Lcobucci\JWT\Storage\Parser::parseHeader
     * @covers \Lcobucci\JWT\Storage\Parser::parseClaims
     * @covers \Lcobucci\JWT\Storage\Parser::parseSignature
     */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded()
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none', 'aud' => 'test']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none', 'aud' => 'test'], 'a');
        $claims = new DataSet(['aud' => 'test'], 'b');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals(null, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Parser::__construct
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Parser::parse
     * @covers \Lcobucci\JWT\Storage\Parser::createToken
     * @covers \Lcobucci\JWT\Storage\Parser::splitJwt
     * @covers \Lcobucci\JWT\Storage\Parser::parseHeader
     * @covers \Lcobucci\JWT\Storage\Parser::parseClaims
     * @covers \Lcobucci\JWT\Storage\Parser::parseSignature
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsMissing()
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $headers = new DataSet(['typ' => 'JWT'], 'a');
        $claims = new DataSet(['aud' => 'test'], 'b');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals(null, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Parser::__construct
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Parser::parse
     * @covers \Lcobucci\JWT\Storage\Parser::createToken
     * @covers \Lcobucci\JWT\Storage\Parser::splitJwt
     * @covers \Lcobucci\JWT\Storage\Parser::parseHeader
     * @covers \Lcobucci\JWT\Storage\Parser::parseClaims
     * @covers \Lcobucci\JWT\Storage\Parser::parseSignature
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsNone()
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims = new DataSet(['aud' => 'test'], 'b');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals(null, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Parser::__construct
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\Signature
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Parser::parse
     * @covers \Lcobucci\JWT\Storage\Parser::createToken
     * @covers \Lcobucci\JWT\Storage\Parser::splitJwt
     * @covers \Lcobucci\JWT\Storage\Parser::parseHeader
     * @covers \Lcobucci\JWT\Storage\Parser::parseClaims
     * @covers \Lcobucci\JWT\Storage\Parser::parseSignature
     */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed()
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn(['aud' => 'test']);

        $this->decoder->expects($this->at(4))
                      ->method('base64UrlDecode')
                      ->with('c')
                      ->willReturn('c_dec');

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'HS256'], 'a');
        $claims = new DataSet(['aud' => 'test'], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals($signature, 'signature', $token);
    }
}
