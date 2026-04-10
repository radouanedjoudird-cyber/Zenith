import { SetMetadata } from '@nestjs/common';

/**
 * ZENITH ACCESS CONTROL METADATA KEY
 * ----------------------------------
 * Unique identifier used by the PermissionsGuard to extract 
 * required actions from the route handler.
 */
export const PERMISSIONS_KEY = 'permissions';

/**
 * @decorator Permissions
 * @description
 * Enforces Granular Access Control (PBAC) by requiring specific actions.
 * This shifts the security logic from "Who the user is" to "What the user can do".
 * * STRATEGY: 
 * Using string-based actions (e.g., 'USER_READ', 'SYSTEM_AUDIT') provides 
 * maximum flexibility without redeploying code when roles change.
 * * @example
 * @Permissions('USER_DELETE', 'ADMIN_VIEW')
 * @Get(':id')
 * * @param permissions string[] - List of required system actions.
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
export const Permissions = (...permissions: string[]) => 
  SetMetadata(PERMISSIONS_KEY, permissions);