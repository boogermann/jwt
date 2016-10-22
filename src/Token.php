<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use DateTimeInterface;
use Lcobucci\JWT\Storage\DataSet;
use Lcobucci\JWT\Storage\Signature;

/**
 * Basic structure of the JWT
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
interface Token
{
    /**
     * Returns the token headers
     */
    public function headers(): DataSet;

    /**
     * Returns the token claim set
     */
    public function claims(): DataSet;

    /**
     * @return Signature|null
     */
    public function signature();

    /**
     * Determine if the token is expired.
     *
     * @param DateTimeInterface $now Defaults to the current time.
     */
    public function isExpired(DateTimeInterface $now = null): bool;

    /**
     * Returns the token payload
     */
    public function payload(): string;

    /**
     * Returns an encoded representation of the token
     */
    public function __toString(): string;
}
