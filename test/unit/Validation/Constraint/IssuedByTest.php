<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

final class IssuedByTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy::assert
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldRaiseExceptionWhenIssuerIsNotSet()
    {
        $constraint = new IssuedBy('test.com', 'test.net');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy::assert
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldRaiseExceptionWhenIssuerValueDoesNotMatch()
    {
        $constraint = new IssuedBy('test.com', 'test.net');
        $constraint->assert($this->buildToken(['iss' => 'example.com']));
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy::assert
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldRaiseExceptionWhenIssuerTypeValueDoesNotMatch()
    {
        $constraint = new IssuedBy('test.com', '123');
        $constraint->assert($this->buildToken(['iss' => 123]));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy::assert
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldNotRaiseExceptionWhenIssuerMatches()
    {
        $token = $this->buildToken(['iss' => 'test.com']);
        $constraint = new IssuedBy('test.com', 'test.net');

        self::assertNull($constraint->assert($token));
    }
}
