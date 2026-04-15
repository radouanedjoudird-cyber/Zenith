/**
 * ZENITH SYSTEMS - CORE IDENTITY SEEDING ENGINE v5.0 (Enterprise Edition)
 * -----------------------------------------------------------------------------
 * MISSION: Provisioning the initial root administrative identity for MongoDB.
 * * ARCHITECTURAL STANDARDS:
 * 1. ATOMICITY: Ensures consistent state across the identity registry.
 * 2. CRYPTO_COMPLIANCE: Enforces Argon2id (Memory-hard hashing standard).
 * 3. SESSION_AWARENESS: Initializes session telemetry for the root identity.
 * 4. IDEMPOTENCY: Guard clauses prevent duplicate identity deployment.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */

import { PrismaClient, Role } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  console.log('🚀 [ZENITH_INFRA]: Initializing High-Entropy Identity Deployment...');

  /**
   * SECURITY CONFIGURATION:
   * Root Administrator parameters for the distributed ecosystem.
   */
  const adminEmail = 'admin@zenith-systems.dz';
  const adminPassword = 'Zenith@2026!SecureAdmin';

  /**
   * GLOBAL PERMISSION MATRIX:
   * Atomic permission set for the Zenith Shield kernel (PBAC Model).
   */
  const systemPermissions = [
    'PROFILE_READ',      // Access to self-identity data
    'PROFILE_UPDATE',    // Identity modification rights
    'AUTH_STATUS_VIEW',  // Session integrity auditing
    'USER_VIEW_ALL',     // Global registry lookup
    'USER_VIEW_SINGLE',  // Targeted identity inspection
    'USER_UPDATE_ANY',   // Elevated user modification
    'USER_DELETE_ANY',   // Global identity purge
    'SYSTEM_AUDIT_READ', // Access to the AuditLog ledger
    'SECURITY_LOGS_VIEW' // Real-time security telemetry access
  ];

  /**
   * ATOMIC UPSERT SEQUENCE:
   * Utilizing Upsert to ensure idempotency and prevent registry collision.
   */
  const hashedPassword = await argon2.hash(adminPassword);

  console.log(`📡 [ZENITH_IAM]: Provisioning Root Authority: ${adminEmail}`);

  const admin = await prisma.user.upsert({
    where: { email: adminEmail },
    update: {
      password: hashedPassword, // Synchronize to Argon2id standard
      role: Role.SUPER_ADMIN,
    },
    create: {
      email: adminEmail,
      password: hashedPassword,
      firstName: 'Zenith',
      familyName: 'Root',
      phoneNumber: '+213000000000',
      role: Role.SUPER_ADMIN,
      // Nested permission provisioning
      permissions: {
        createMany: {
          data: systemPermissions.map((action) => ({ action })),
        },
      },
    },
    include: { sessions: true },
  });

  /**
   * SESSION REGISTRY INITIALIZATION:
   * Ensures the Multi-Device Session model is operational post-deployment.
   * This mimics a 'System Session' for infra-level tasks.
   */
  if (admin.sessions.length === 0) {
    const systemRtHash = await argon2.hash('SYSTEM_INITIALIZATION_TOKEN');
    await prisma.session.create({
      data: {
        userId: admin.id,
        hashedRt: systemRtHash,
        userAgent: 'Zenith-Infra-Kernel/5.0 (Seed Engine)',
        ipAddress: '127.0.0.1',
      },
    });
    console.log('🛡️ [ZENITH_SESSION]: Primary infrastructure session context anchored.');
  }

  console.log(`✅ [ZENITH_SUCCESS]: Root identity secured with Argon2id and ${systemPermissions.length} claims.`);
}

/**
 * KERNEL EXECUTION & ERROR TELEMETRY
 */
main()
  .catch((error) => {
    console.error('🔴 [CRITICAL_FAILURE]: Identity seeding aborted by Kernel.');
    console.error(`ERROR_DETAILS: ${error.message}`);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    console.log('🔌 [ZENITH_INFRA]: Security connection pool released.');
  });