/**
 * ZENITH SYSTEMS - CORE IDENTITY SEEDING ENGINE v2.8
 * --------------------------------------------------
 * MISSION: Provisioning the initial root administrative identity and PBAC matrix.
 * * ARCHITECTURAL STANDARDS:
 * 1. ATOMICITY: Leverages Prisma Transactions ($transaction) to ensure database consistency.
 * 2. SECURITY: 12-round Bcrypt salt cost optimized for high-entropy password storage.
 * 3. IDEMPOTENCY: Guard clauses prevent duplicate execution and data corruption.
 * 4. PBAC READINESS: Injects the full Granular Permission set for the root administrator.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */

import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🚀 [ZENITH_INFRA]: Initializing PBAC identity deployment...');

  /**
   * SECURITY CONFIGURATION:
   * Root Administrator identity parameters. 
   * In a CI/CD pipeline, these should be sourced via process.env.
   */
  const adminEmail = 'admin@zenith-systems.dz';
  const adminPassword = 'Zenith@2026!SecureAdmin';

  /**
   * GLOBAL PERMISSION MATRIX:
   * Defining the core 'Actions' required to navigate the Zenith Shield.
   * These keys must match the @Permissions() decorators in the controllers.
   */
  const systemPermissions = [
    // --- MODULE: IDENTITY & ACCESS ---
    'PROFILE_READ',      // Self-profile access
    'PROFILE_UPDATE',    // Identity modification
    'PROFILE_DELETE',    // Self-termination
    'AUTH_STATUS_VIEW',  // Session claim auditing
    
    // --- MODULE: ADMINISTRATIVE GOVERNANCE ---
    'USER_VIEW_ALL',     // Global registry lookup
    'USER_VIEW_SINGLE',  // Targeted identity lookup
    'USER_UPDATE_ANY',   // Elevated user modification
    'USER_DELETE_ANY',   // Elevated user purge
    
    // --- MODULE: FORENSIC & SYSTEM ---
    'SYSTEM_AUDIT_READ', // Access to the AuditLog registry
    'SECURITY_LOGS_VIEW' // Real-time security telemetry access
  ];

  // IDEMPOTENCY CHECK: Guard against duplicate seeding
  const existingAdmin = await prisma.user.findUnique({
    where: { email: adminEmail },
  });

  if (!existingAdmin) {
    console.log(`📡 [ZENITH_AUTH]: Provisioning new Root Admin: ${adminEmail}`);
    
    const hashedPassword = await bcrypt.hash(adminPassword, 12);

    /**
     * ATOMIC TRANSACTIONAL DEPLOYMENT:
     * Ensuring that both the User identity and their Permission set are created
     * simultaneously to prevent "Orphaned Admins" with zero permissions.
     */
    await prisma.$transaction(async (tx) => {
      // Step 1: Create the Primary Identity
      const admin = await tx.user.create({
        data: {
          email: adminEmail,
          password: hashedPassword,
          firstName: 'Zenith',
          familyName: 'Root',
          phoneNumber: '+213000000000', // Compliance with @unique constraint
          role: Role.SUPER_ADMIN,       // Maximum privilege tier
        },
      });

      // Step 2: Inject the Permission Matrix (PBAC)
      await tx.userPermission.createMany({
        data: systemPermissions.map((action) => ({
          action,
          userId: admin.id,
        })),
      });
    });

    console.log(`✅ [ZENITH_SUCCESS]: Root identity and ${systemPermissions.length} permissions secured.`);
  } else {
    console.log('⚠️ [ZENITH_SEED]: Admin identity detected. Skipping provisioning to maintain data integrity.');
  }
}

/**
 * LIFECYCLE MANAGEMENT:
 * Proper resource cleanup and error propagation for Linux/Unix environments.
 */
main()
  .catch((error) => {
    console.error('🔴 [CRITICAL_FAILURE]: Identity seeding aborted:');
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    // Terminate DB connection pool to prevent memory leaks on the HP-ProBook
    await prisma.$disconnect();
    console.log('🔌 [ZENITH_INFRA]: Database connection pool released.');
  });