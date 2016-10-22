<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Storage;

use DateTime;
use DateTimeInterface;
use Lcobucci\JWT\Token as TokenInterface;

/**
 * Basic structure of the JWT
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class Token implements TokenInterface
{
    /**
     * The token headers
     *
     * @var DataSet
     */
    private $headers;

    /**
     * The token claim set
     *
     * @var DataSet
     */
    private $claims;

    /**
     * The token signature
     *
     * @var Signature|null
     */
    private $signature;

    /**
     * Initializes the object
     *
     * @param DataSet $headers
     * @param DataSet $claims
     * @param Signature|null $signature
     */
    public function __construct(
        DataSet $headers,
        DataSet $claims,
        Signature $signature = null
    ) {
        $this->headers = $headers;
        $this->claims = $claims;
        $this->signature = $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function headers(): DataSet
    {
        return $this->headers;
    }

    /**
     * {@inheritdoc}
     */
    public function claims(): DataSet
    {
        return $this->claims;
    }

    /**
     * {@inheritdoc}
     */
    public function signature()
    {
        return $this->signature;
    }

    /**
     * {@inheritdoc}
     */
    public function isExpired(DateTimeInterface $now = null): bool
    {
        if (!$this->claims->has('exp')) {
            return false;
        }

        $now = $now ?: new DateTime();

        return $now->getTimestamp() > $this->claims->get('exp');
    }

    /**
     * {@inheritdoc}
     */
    public function payload(): string
    {
        return $this->headers . '.' . $this->claims;
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return implode('.', get_object_vars($this));
    }
}
