<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeImmutable;

final class ValidAtTest extends ConstraintTestCase
{
    /**
     * @var DateTimeImmutable
     */
    private $now;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->now = new DateTimeImmutable();
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldRaiseExceptionWhenTokenIsExpired()
    {
        $currentTime = $this->now->getTimestamp();

        $claims = [
            'iat' => $currentTime - 20,
            'nbf' => $currentTime - 10,
            'exp' => $currentTime - 10,
        ];

        $constraint = new ValidAt($this->now);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertBeforeThanNow
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldRaiseExceptionWhenMinimumTimeIsNotMet()
    {
        $currentTime = $this->now->getTimestamp();

        $claims = [
            'iat' => $currentTime - 20,
            'nbf' => $currentTime + 40,
            'exp' => $currentTime + 60,
        ];

        $constraint = new ValidAt($this->now);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertBeforeThanNow
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldRaiseExceptionWhenTokenWasIssuedInTheFuture()
    {
        $currentTime = $this->now->getTimestamp();

        $claims = [
            'iat' => $currentTime + 20,
            'nbf' => $currentTime + 40,
            'exp' => $currentTime + 60,
        ];

        $constraint = new ValidAt($this->now);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertBeforeThanNow
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldNotRaiseExceptionWhenTokenIsUsedInTheRightMoment()
    {
        $currentTime = $this->now->getTimestamp();
        $constraint = new ValidAt($this->now);

        $token = $this->buildToken(
            [
                'iat' => $currentTime - 40,
                'nbf' => $currentTime - 20,
                'exp' => $currentTime + 60,
            ]
        );

        self::assertNull($constraint->assert($token));

        $token = $this->buildToken(
            [
                'iat' => $currentTime,
                'nbf' => $currentTime,
                'exp' => $currentTime + 60,
            ]
        );

        self::assertNull($constraint->assert($token));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertBeforeThanNow
     *
     * @uses \Lcobucci\JWT\Storage\DataSet
     * @uses \Lcobucci\JWT\Storage\Token
     */
    public function assertShouldNotRaiseExceptionWhenTokenDoesNotHaveTimeClais()
    {
        $token = $this->buildToken();
        $constraint = new ValidAt($this->now);
        self::assertNull($constraint->assert($token));
    }
}
