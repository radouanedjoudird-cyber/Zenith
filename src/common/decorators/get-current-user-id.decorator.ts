import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * GET CURRENT USER ID DECORATOR
 * ----------------------------
 * A custom parameter decorator that extracts the 'sub' field (User ID)
 * from the JWT payload after it has been validated by the AtGuard.
 * * BEST PRACTICE: Decouples the Controller from the Request object.
 */
export const GetCurrentUserId = createParamDecorator(
  (_: undefined, context: ExecutionContext): number => {
    // Switch to HTTP context to access the request object
    const request = context.switchToHttp().getRequest();
    
    // The 'user' object is attached to the request by Passport.js
    // We return the 'sub' (Subject) which contains our User ID.
    return request.user?.sub;
  },
);