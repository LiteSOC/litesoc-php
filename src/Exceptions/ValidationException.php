<?php

declare(strict_types=1);

namespace LiteSOC\Exceptions;

/**
 * Exception thrown when request validation fails (400 Bad Request)
 *
 * This indicates the request contains invalid parameters,
 * malformed JSON, or fails schema validation.
 */
class ValidationException extends LiteSOCException
{
    public function __construct(
        string $message = 'Invalid request',
        ?string $responseBody = null,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 400, $responseBody, $previous);
    }
}
