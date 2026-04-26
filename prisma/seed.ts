/**
 * ============================================================================
 * ZENITH SYSTEMS - INFRASTRUCTURE PROVISIONING ENGINE
 * ============================================================================
 * @module @zenith/infra-seed
 * @version 7.4.0
 * @author Radouane Djoudi
 * @license Proprietary - Zenith Secure Systems
 * * @description 
 * Manages the idempotent deployment of the core RBAC (Role-Based Access Control) 
 * matrix and provisions the root authority identity. 
 * * ARCHITECTURAL DESIGN:
 * 1. ATOMIC_UPSERT: Ensures that repeated executions do not corrupt data integrity.
 * 2. ARGON2ID_COMPLIANCE: Utilizes NIST-recommended hashing for the root anchor.
 * 3. TELEMETRY_INITIALIZATION: Deploys the first forensic session for system audit.
 * ============================================================================
 */

import { AccountStatus, PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';

/** @constant {PrismaClient} prisma - Orchestration layer for MongoDB persistence */
const prisma = new PrismaClient();

/**
 * @function main
 * @async
 * @description Entry point for the infrastructure seeding lifecycle.
 * @returns {Promise<void>}
 */
async function main(): Promise<void> {
  console.log('🚀 [ZENITH_INFRA]: Initializing Dynamic Policy Deployment...');

  // [1] RBAC MATRIX DEFINITION
  // ---------------------------------------------------------------------------
  const rolesMetadata = [
    {
      name: 'SUPERADMIN',
      description: 'Full-spectrum system authority with kernel-level access.',
      permissions: ['*'], 
    },
    {
      name: 'ADMIN',
      description: 'Administrative control over user management and audits.',
      permissions: ['USER_READ', 'USER_WRITE', 'AUDIT_VIEW', 'REPORT_GENERATE'],
    },
    {
      name: 'USER',
      description: 'Standard consumer identity with limited self-service access.',
      permissions: ['PROFILE_READ', 'PROFILE_UPDATE'],
    },
  ];

  console.log('📡 [ZENITH_RBAC]: Synchronizing policy registry...');
  
  for (const role of rolesMetadata) {
    await prisma.role.upsert({
      where: { name: role.name },
      update: { 
        permissions: role.permissions,
        updatedAt: new Date()
      },
      create: {
        name: role.name,
        description: role.description,
        permissions: role.permissions,
      },
    });
  }

  // [2] ROOT AUTHORITY PROVISIONING (The Zero-Trust Anchor)
  // ---------------------------------------------------------------------------
  const rootEmail = 'admin@zenith-systems.dz';
  const rootPassword = 'Zenith@2026!Admin'; // Match agreed credentials
  
  const hashedPassword = await argon2.hash(rootPassword, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,
    timeCost: 3,
    parallelism: 1
  });

  const superAdminRole = await prisma.role.findUnique({ where: { name: 'SUPERADMIN' } });

  if (!superAdminRole) {
    throw new Error('🔴 [SEED_ERROR]: Execution halted. SUPERADMIN role context not found.');
  }

  console.log(`🔑 [ZENITH_IAM]: Anchoring Root Authority: ${rootEmail}`);

  const rootUser = await prisma.user.upsert({
    where: { email: rootEmail },
    update: {
      password: hashedPassword,
      roleId: superAdminRole.id,
      status: AccountStatus.ACTIVE,
    },
    create: {
      email: rootEmail,
      password: hashedPassword,
      firstName: 'Zenith',
      familyName: 'Kernel',
      phoneNumber: '+213000000000',
      roleId: superAdminRole.id,
      status: AccountStatus.ACTIVE,
      version: 1,
    },
  });

  // [3] FORENSIC SESSION TELEMETRY
  // ---------------------------------------------------------------------------
  const rootSessionExpiry = new Date();
  rootSessionExpiry.setFullYear(rootSessionExpiry.getFullYear() + 1); // 1-year persistence

  /**
   * Ensuring a clean forensic record for the initial deployment.
   * This anchors the hardware-bound session for the first login attempt.
   */
  await prisma.session.deleteMany({ where: { userId: rootUser.id } });

  const systemRtHash = await argon2.hash('BOOTSTRAP_INITIALIZATION_SECRET_2026');
  
  await prisma.session.create({
    data: {
      userId: rootUser.id,
      hashedRt: systemRtHash,
      deviceId: 'ZENITH-INFRA-ROOT-01',
      os: 'ZenithOS/Kernel',
      browser: 'System-Seed-Engine',
      ipAddress: '127.0.0.1',
      expiresAt: rootSessionExpiry,
    },
  });

  console.log('🛡️ [ZENITH_SESSION]: Forensic session anchor deployed.');
  console.log('✅ [ZENITH_SUCCESS]: Infrastructure provisioning complete.');
}

/**
 * EXECUTION_HOOK
 * Handles lifecycle events and pool management.
 */
main()
  .catch((e: Error) => {
    console.error('🔴 [CRITICAL_BOOT_FAILURE]: Core Provisioning Aborted.');
    console.error(`Reason: ${e.message}`);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    console.log('🔌 [ZENITH_INFRA]: Connectivity pool released.');
  });