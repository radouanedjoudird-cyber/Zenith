import { SetMetadata } from '@nestjs/common';
import { Role } from '../enums/role.enum';

/**
 * Metadata key for Role-Based Access Control.
 */
export const ROLES_KEY = 'roles';

/**
 * @function Roles
 * @description Decorator to restrict access based on user hierarchy.
 * @example @Roles(Role.ADMIN)
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);