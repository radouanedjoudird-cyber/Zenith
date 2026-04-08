import { SetMetadata } from '@nestjs/common';
import { Role } from '@prisma/client'; // Direct reference to Prisma Enum

/**
 * @constant ROLES_KEY
 * @description Unique identifier for role metadata storage.
 */
export const ROLES_KEY = 'roles';

/**
 * @decorator Roles
 * @description 
 * Grants access based on user roles. Works seamlessly with Prisma-defined roles.
 * Usage: @Roles(Role.ADMIN)
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);