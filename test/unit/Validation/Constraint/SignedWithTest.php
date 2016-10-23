<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Storage\Signature;

final class SignedWithTest extends ConstraintTestCase
{
    /**
     * @var Signer|\PHPUnit_Framework_MockObject_MockObject
     */
    private $signer;

    /**
     * @var Signer\Key
     */
    private $key;

    /**
     * @var Signature
     */
    private $signature;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->signer = $this->createMock(Signer::class);
        $this->signer->method('getAlgorithmId')->willReturn('RS256');

        $this->key = new Signer\Key('123');
        $this->signature = new Signature('1234', '5678');
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\Signature
     * @uses \Lcobucci\JWT\Storage\Signature
     */
    public function assertShouldRaiseExceptionWhenTokenIsUnsigned()
    {
        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\Signature
     */
    public function assertShouldRaiseExceptionWhenSignerIsNotTheSame()
    {
        $token = $this->buildToken([], ['alg' => 'test'], $this->signature);

        $this->signer->expects($this->never())->method('verify');

        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($token);
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\Signature
     */
    public function assertShouldRaiseExceptionWhenSignatureIsInvalid()
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);

        $this->signer->expects($this->once())
                     ->method('verify')
                     ->with($this->signature->hash(), $token->payload(), $this->key)
                     ->willReturn(false);

        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($token);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     * @uses \Lcobucci\JWT\Storage\Signature
     */
    public function assertShouldRaiseExceptionWhenSignatureIsValid()
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);

        $this->signer->expects($this->once())
                     ->method('verify')
                     ->with($this->signature->hash(), $token->payload(), $this->key)
                     ->willReturn(true);

        $constraint = new SignedWith($this->signer, $this->key);
        self::assertNull($constraint->assert($token));
    }
}
