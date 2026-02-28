<?php

declare(strict_types=1);

namespace LiteSOC\Exceptions;

/**
 * Exception thrown when API authentication fails (401 Unauthorized)
 *
 * This typically indicates an invalid or missing API key.
 */
class AuthenticationException extends LiteSOCException
{
    public function __construct(
        string $message = 'Invalid or missing API key',
        ?string $responseBody = null,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 401, $responseBody, $previous);
    }
}
