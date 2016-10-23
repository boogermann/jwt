<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Exception;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 4.0.0
 */
final class InvalidTokenException extends Exception
{
    /**
     * @var ConstraintViolationException[]
     */
    private $violations;

    public static function fromViolations(ConstraintViolationException ...$violations): self
    {
        $exception = new self('The token violates some mandatory constraints');
        $exception->violations = $violations;

        return $exception;
    }

    public function violations(): array
    {
        return $this->violations;
    }
}
