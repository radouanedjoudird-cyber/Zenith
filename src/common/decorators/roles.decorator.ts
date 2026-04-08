import { SetMetadata } from '@nestjs/common';
import { Role } from '../enums/role.enum';

/**
 * ZENITH ACCESS CONTROL DECORATOR
 * ------------------------------
 * This decorator allows specifying which roles are permitted to access a route.
 * It uses 'SetMetadata' to attach the required roles to the request handler.
 */
export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);