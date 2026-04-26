import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * ZENITH SUB EXTRACTOR
 * --------------------
 * A custom parameter decorator that extracts the 'sub' field (User ID)
 * from the JWT payload after Passport validation.
 * BEST PRACTICE: Decouples the Controller from the Request object structure.
 */
export const GetCurrentUserId = createParamDecorator(
  (_: undefined, context: ExecutionContext): number => {
    const request = context.switchToHttp().getRequest();
    
    // Maps to request.user.sub established in JwtStrategy.validate()
    return request.user?.sub;
  },
);