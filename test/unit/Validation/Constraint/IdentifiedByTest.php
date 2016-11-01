<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

final class IdentifiedByTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::assert
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldRaiseExceptionWhenIdIsNotSet()
    {
        $constraint = new IdentifiedBy('123456');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::assert
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldRaiseExceptionWhenIdDoesNotMatch()
    {
        $constraint = new IdentifiedBy('123456');
        $constraint->assert($this->buildToken(['jti' => 15]));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::assert
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldNotRaiseExceptionWhenIdMatches()
    {
        $token = $this->buildToken(['jti' => '123456']);

        $constraint = new IdentifiedBy('123456');
        self::assertNull($constraint->assert($token));
    }
}
