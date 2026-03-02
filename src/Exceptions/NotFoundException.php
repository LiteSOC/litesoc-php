<?php

declare(strict_types=1);

namespace LiteSOC\Exceptions;

/**
 * Exception thrown when a resource is not found (404 Not Found)
 *
 * This typically indicates the requested alert, event, or other
 * resource does not exist or is not accessible to the current API key.
 */
class NotFoundException extends LiteSOCException
{
    public function __construct(
        string $message = 'Resource not found',
        ?string $responseBody = null,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 404, $responseBody, $previous);
    }
}
