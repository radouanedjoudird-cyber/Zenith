import { createParamDecorator, ExecutionContext, InternalServerErrorException } from '@nestjs/common';

/**
 * @namespace Zenith.Common.Decorators
 * @author Radouane Djoudi
 * @version 1.1.0
 */

/**
 * 🛡️ ZENITH IDENTITY PROVIDER DECORATOR
 * ------------------------------------
 * @function GetCurrentUserId
 * @description
 * High-integrity parameter decorator designed to extract the Subject Identifier (`sub`) 
 * from the validated OIDC-compliant JWT payload. This decorator acts as a bridge 
 * between the Passport.js authentication layer and the domain services.
 *
 * @param {keyof JwtPayload | undefined} data - Optional specific property to extract from the payload.
 * @param {ExecutionContext} context - The NestJS execution context providing access to the HTTP request.
 * * @returns {string} The unique UUID/ObjectID of the authenticated subject.
 * * @throws {InternalServerErrorException} 
 * Thrown if the execution context is accessed without a valid 'user' object, 
 * typically indicating a missing or misconfigured @UseGuards(AtGuard).
 * * @example
 * // Usage in Controller:
 * getMe(@GetCurrentUserId() userId: string) { ... }
 * * @security
 * - Scope: Authentication-dependent.
 * - Integrity: Guaranteed via JWT Signature verification prior to extraction.
 * - Privacy: Returns only the subject identifier, adhering to the Principle of Least Privilege.
 */
export const GetCurrentUserId = createParamDecorator(
  (data: undefined, context: ExecutionContext): string => {
    const request = context.switchToHttp().getRequest();
    
    /**
     * @constant {any} user - The identity payload attached to the request by the AuthGuard.
     */
    const user = request.user;

    // 🔴 Defensive Validation: Ensure the IAM context is not corrupted
    if (!user || !user.sub) {
      throw new InternalServerErrorException({
        code: 'ZENITH_IAM_DECORATOR_FAULT',
        message: 'Security context is missing or sub identifier is undefined.',
        trace: 'Ensure @UseGuards(AtGuard) is present on the controller method.',
      });
    }

    /**
     * @returns The Subject Identifier (sub)
     * Note: Casted to string to maintain compatibility with Zenith Registry (MongoDB/PostgreSQL).
     */
    return user.sub as string;
  },
);