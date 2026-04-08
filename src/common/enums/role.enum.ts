/**
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM)
 * ----------------------------------------
 * Defines strict user roles to be used across the application.
 * These values must align perfectly with the Prisma Schema Enums.
 */
export enum Role {
  USER = 'USER',
  ADMIN = 'ADMIN',
  MODERATOR = 'MODERATOR',
}