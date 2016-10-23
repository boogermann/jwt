<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation;

final class InvalidTokenExceptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException::fromViolations
     */
    public function fromViolationsShouldConfigureMessageAndViolationList()
    {
        $violation = new ConstraintViolationException();
        $exception = InvalidTokenException::fromViolations($violation);

        self::assertAttributeEquals(
            'The token violates some mandatory constraints',
            'message',
            $exception
        );

        self::assertAttributeSame([$violation], 'violations', $exception);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException::violations
     *
     * @uses \Lcobucci\JWT\Validation\InvalidTokenException::fromViolations
     */
    public function violationsShouldReturnTheViolationList()
    {
        $violation = new ConstraintViolationException();
        $exception = InvalidTokenException::fromViolations($violation);

        self::assertSame([$violation], $exception->violations());
    }
}
