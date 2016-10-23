<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;

final class ValidatorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Token|\PHPUnit_Framework_MockObject_MockObject
     */
    private $token;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->token = $this->createMock(Token::class);
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\InvalidTokenException
     *
     * @covers \Lcobucci\JWT\Validation\Validator::validate
     * @covers \Lcobucci\JWT\Validation\Validator::assert
     *
     * @uses \Lcobucci\JWT\Validation\InvalidTokenException
     */
    public function validateShouldRaiseExceptionWhenAtLeastOneConstraintFails()
    {
        $failedConstraint = $this->createMock(Constraint::class);
        $successfulConstraint = $this->createMock(Constraint::class);

        $failedConstraint->expects($this->once())
                         ->method('assert')
                         ->willThrowException(new ConstraintViolationException());

        $successfulConstraint->expects($this->once())
                             ->method('assert');

        $validator = new Validator();

        $validator->validate(
            $this->token,
            $failedConstraint,
            $successfulConstraint
        );
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Validator::validate
     * @covers \Lcobucci\JWT\Validation\Validator::assert
     */
    public function validateShouldNotRaiseExceptionWhenNoConstraintFails()
    {
        $constraint = $this->createMock(Constraint::class);
        $constraint->expects($this->once())->method('assert');

        $validator = new Validator();
        self::assertNull($validator->validate($this->token, $constraint));
    }
}
