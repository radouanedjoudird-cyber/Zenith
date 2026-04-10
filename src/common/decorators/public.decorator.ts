import { SetMetadata } from '@nestjs/common';

/**
 * @Public Decorator
 * -----------------
 * Bypass the Global AtGuard for specific endpoints (e.g., Login, Signup).
 */
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);