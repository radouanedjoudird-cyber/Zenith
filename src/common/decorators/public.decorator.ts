/**
 * @fileoverview SECURITY INFRASTRUCTURE - PUBLIC DECORATOR
 * @version 1.0.0
 * @description Defines a metadata marker to bypass Global Guards.
 * * DESIGN PATTERN: Metadata Reflection
 * PURPOSE: This decorator is used to mark specific endpoints (like /metrics or /login) 
 * as "Public", instructing the AtGuard to skip JWT verification.
 */

import { SetMetadata } from '@nestjs/common';

/**
 * UNIQUE IDENTIFIER:
 * Used by the Reflector service to identify public routes in the execution context.
 */
export const IS_PUBLIC_KEY = 'isPublic';

/**
 * @function Public
 * @description The core decorator to be applied on controllers or specific handlers.
 * @example
 * @Public()
 * @Get('metrics')
 * getMetrics() { ... }
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);