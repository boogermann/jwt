<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeInterface;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolationException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class ValidAt implements Constraint
{
    /**
     * @var DateTimeInterface
     */
    private $now;

    public function __construct(DateTimeInterface $now)
    {
        $this->now = $now;
    }

    /**
     * {@inheritdoc}
     */
    public function assert(Token $token)
    {
        $claimSet = $token->claims();

        $this->assertExpiration($token);
        $this->assertBeforeThanNow($claimSet->get('nbf'), 'The token cannot be used yet');
        $this->assertBeforeThanNow($claimSet->get('iat'), 'The token was issued in the future');
    }

    /**
     * @throws ConstraintViolationException
     */
    private function assertExpiration(Token $token)
    {
        if ($token->isExpired($this->now)) {
            throw new ConstraintViolationException('The token is expired');
        }
    }

    /**
     * @throws ConstraintViolationException
     */
    private function assertBeforeThanNow(int $claim = null, string $message)
    {
        if ($claim > $this->now->getTimestamp()) {
            throw new ConstraintViolationException($message);
        }
    }
}
