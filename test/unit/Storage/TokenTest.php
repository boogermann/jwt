<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Storage;

use DateTime;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class TokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var DataSet
     */
    private $headers;

    /**
     * @var DataSet
     */
    private $claims;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->headers = new DataSet(['alg' => 'none'],  'headers');
        $this->claims = new DataSet([],  'claims');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Token::__construct
     */
    public function constructMustInitializeAnEmptyPlainTextTokenWhenNoArgumentsArePassed()
    {
        $token = new Token($this->headers, $this->claims);

        self::assertAttributeSame($this->headers, 'headers', $token);
        self::assertAttributeSame($this->claims, 'claims', $token);
        self::assertAttributeEquals(null, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Token::headers
     */
    public function headersMustReturnTheConfiguredDataSet()
    {
        $token = new Token($this->headers, $this->claims);

        self::assertSame($this->headers, $token->headers());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Token::claims
     */
    public function claimsMustReturnTheConfiguredClaims()
    {
        $token = new Token($this->headers, $this->claims);

        self::assertSame($this->claims, $token->claims());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Storage\Token::isExpired
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\Token::claims
     * @uses \Lcobucci\JWT\Storage\DataSet
     */
    public function isExpiredShouldReturnFalseWhenTokenDoesNotExpires()
    {
        $token = new Token($this->headers, $this->claims);

        self::assertFalse($token->isExpired());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Storage\Token::isExpired
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\Token::claims
     * @uses \Lcobucci\JWT\Storage\DataSet
     */
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired()
    {
        $token = new Token(
            $this->headers,
            new DataSet(['exp' => time() + 500], '')
        );

        self::assertFalse($token->isExpired());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Storage\Token::isExpired
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\Token::claims
     * @uses \Lcobucci\JWT\Storage\DataSet
     */
    public function isExpiredShouldReturnFalseWhenExpirationIsEqualsToNow()
    {
        $now = new DateTime();
        $token = new Token(
            $this->headers,
            new DataSet(['exp' => $now->getTimestamp()], '')
        );

        self::assertFalse($token->isExpired($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Storage\Token::isExpired
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\Token::claims
     * @uses \Lcobucci\JWT\Storage\DataSet
     */
    public function isExpiredShouldReturnTrueAfterTokenExpires()
    {
        $token = new Token(
            $this->headers,
            new DataSet(['exp' => time()], '')
        );

        self::assertTrue($token->isExpired(new DateTime('+10 days')));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Token::payload
     */
    public function payloadShouldReturnAStringWithTheEncodedHeadersAndClaims()
    {
        $token = new Token($this->headers, $this->claims);

        self::assertEquals('headers.claims', $token->payload());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Token::signature
     */
    public function signatureShouldReturnNullWhenSignatureIsNotConfigured()
    {
        $token = new Token($this->headers, $this->claims);

        self::assertNull($token->signature());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Signature
     *
     * @covers \Lcobucci\JWT\Storage\Token::signature
     */
    public function signatureShouldReturnTheConfiguredSignature()
    {
        $signature = new Signature('hash', 'signature');
        $token = new Token($this->headers, $this->claims, $signature);

        self::assertSame($signature, $token->signature());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\Token::payload
     * @uses \Lcobucci\JWT\Storage\DataSet
     *
     * @covers \Lcobucci\JWT\Storage\Token::__toString
     */
    public function toStringMustReturnEncodedDataWithEmptySignature()
    {
        $token = new Token($this->headers, $this->claims);

        self::assertEquals('headers.claims.', (string) $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Storage\Token::__construct
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Signature
     *
     * @covers \Lcobucci\JWT\Storage\Token::__toString
     */
    public function toStringMustReturnEncodedData()
    {
        $token = new Token(
            $this->headers,
            $this->claims,
            new Signature('hash', 'signature')
        );

        self::assertEquals('headers.claims.signature', (string) $token);
    }
}
