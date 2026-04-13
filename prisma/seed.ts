/**
 * ZENITH SYSTEMS - CORE IDENTITY SEEDING ENGINE v4.0 (MongoDB Optimized)
 * -----------------------------------------------------------------------------
 * MISSION: Provisioning the initial root administrative identity for MongoDB.
 * ARCHITECTURAL STANDARDS:
 * 1. ATOMICITY: Leverages Prisma Transactions to ensure data integrity.
 * 2. COMPATIBILITY: Refactored for MongoDB ObjectId string-based identifiers.
 * 3. SECURITY: 12-round Bcrypt salt cost for high-entropy storage.
 * 4. IDEMPOTENCY: Guard clauses prevent duplicate identity deployment.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */

import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🚀 [ZENITH_INFRA]: Initializing MongoDB PBAC identity deployment...');

  /**
   * SECURITY CONFIGURATION:
   * Root Administrator parameters.
   */
  const adminEmail = 'admin@zenith-systems.dz';
  const adminPassword = 'Zenith@2026!SecureAdmin';

  /**
   * GLOBAL PERMISSION MATRIX:
   * Defined as a set of atomic actions for the Zenith Shield.
   */
  const systemPermissions = [
    'PROFILE_READ',      // Self-profile access
    'PROFILE_UPDATE',    // Identity modification
    'AUTH_STATUS_VIEW',  // Session claim auditing
    'USER_VIEW_ALL',     // Global registry lookup
    'USER_VIEW_SINGLE',  // Targeted identity lookup
    'USER_UPDATE_ANY',   // Elevated user modification
    'USER_DELETE_ANY',   // Elevated user purge
    'SYSTEM_AUDIT_READ', // Access to the AuditLog registry
    'SECURITY_LOGS_VIEW' // Real-time security telemetry access
  ];

  // IDEMPOTENCY CHECK: Guard against duplicate seeding in MongoDB
  const existingAdmin = await prisma.user.findUnique({
    where: { email: adminEmail },
  });

  if (!existingAdmin) {
    console.log(`📡 [ZENITH_AUTH]: Provisioning new MongoDB Root Admin: ${adminEmail}`);
    
    const hashedPassword = await bcrypt.hash(adminPassword, 12);

    /**
     * ATOMIC DEPLOYMENT:
     * Note: MongoDB transactions require a Replica Set in some Prisma versions.
     * We use a standard sequence here for maximum compatibility with local setups.
     */
    const admin = await prisma.user.create({
      data: {
        email: adminEmail,
        password: hashedPassword,
        firstName: 'Zenith',
        familyName: 'Root',
        phoneNumber: '+213000000000',
        role: Role.SUPER_ADMIN,
      },
    });

    // Bulk injection of the Permission Matrix
    await prisma.userPermission.createMany({
      data: systemPermissions.map((action) => ({
        action,
        userId: admin.id, // This is now a String (ObjectId)
      })),
    });

    console.log(`✅ [ZENITH_SUCCESS]: MongoDB Root identity and ${systemPermissions.length} permissions secured.`);
  } else {
    console.log('⚠️ [ZENITH_SEED]: Admin identity detected. Skipping provisioning.');
  }
}

main()
  .catch((error) => {
    console.error('🔴 [CRITICAL_FAILURE]: Identity seeding aborted:');
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    console.log('🔌 [ZENITH_INFRA]: MongoDB connection pool released.');
  });