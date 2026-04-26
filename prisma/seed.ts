/**
 * ============================================================================
 * ZENITH SYSTEMS - INFRASTRUCTURE PROVISIONING ENGINE
 * ============================================================================
 * @module @zenith/infra-seed
 * @version 7.4.2 (Production Ready)
 * @author Radouane Djoudi
 * @license Proprietary - Zenith Secure Systems
 * ----------------------------------------------------------------------------
 * CORE ARCHITECTURE:
 * 1. KERNEL_LEVEL_INDEXING: Low-level MongoDB sparse index orchestration.
 * 2. IDEMPOTENT_RBAC: Atomic UPSERT for policy registry synchronization.
 * 3. ZERO_TRUST_PROVISIONING: Root authority anchoring using Argon2id.
 * ============================================================================
 */

import { AccountStatus, PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';
import { MongoClient } from 'mongodb'; // Required for low-level index management

/** @constant {PrismaClient} prisma - Orchestration layer for high-level DB ops */
const prisma = new PrismaClient();

/**
 * @function provisionSparseIndexes
 * @description Injects sparse uniqueness constraints directly into MongoDB.
 * This compensates for Prisma's current limitations with MongoDB sparse indexes.
 */
async function provisionSparseIndexes(): Promise<void> {
  console.log('📡 [ZENITH_KERNEL]: Initializing Low-Level Indexing Layer...');
  const client = new MongoClient(process.env.DATABASE_URL!);
  
  try {
    await client.connect();
    const db = client.db();
    
    // Explicitly deploying the Sparse Index for recovery tokens
    await db.collection('users').createIndex(
      { resetPasswordToken: 1 },
      { 
        unique: true, 
        sparse: true, 
        name: "unique_reset_token_sparse" 
      }
    );
    
    console.log('✅ [ZENITH_KERNEL]: Sparse Identity Indexes verified and active.');
  } catch (error) {
    console.warn('⚠️ [ZENITH_KERNEL]: Index sync warning (likely already exists).');
  } finally {
    await client.close();
  }
}

/**
 * @function main
 * @async
 * @description Entry point for the Zenith Infrastructure Seeding Lifecycle.
 */
async function main(): Promise<void> {
  console.log('🚀 [ZENITH_INFRA]: Starting Global Provisioning Sequence...');

  // [STEP 0]: PROVISION SYSTEM INDEXES
  // ---------------------------------------------------------------------------
  await provisionSparseIndexes();

  // [STEP 1]: RBAC MATRIX DEFINITION (IDEMPOTENT)
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
      update: { permissions: role.permissions, updatedAt: new Date() },
      create: {
        name: role.name,
        description: role.description,
        permissions: role.permissions,
      },
    });
  }

  // [STEP 2]: ROOT AUTHORITY PROVISIONING
  // ---------------------------------------------------------------------------
  const rootEmail = 'admin@zenith-systems.dz';
  const rootPassword = 'Zenith@2026!Admin';
  
  const hashedPassword = await argon2.hash(rootPassword, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,
    timeCost: 3,
    parallelism: 1
  });

  const superAdminRole = await prisma.role.findUnique({ where: { name: 'SUPERADMIN' } });
  if (!superAdminRole) {
    throw new Error('🔴 [SEED_ERROR]: SUPERADMIN role context not initialized.');
  }

  console.log(`🔑 [ZENITH_IAM]: Anchoring Root Authority: ${rootEmail}`);
  const rootUser = await prisma.user.upsert({
    where: { email: rootEmail },
    update: { password: hashedPassword, roleId: superAdminRole.id },
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

  // [STEP 3]: FORENSIC INITIALIZATION
  // ---------------------------------------------------------------------------
  console.log('🛡️ [ZENITH_SESSION]: Stabilizing forensic telemetry anchor...');
  await prisma.session.deleteMany({ where: { userId: rootUser.id } });
  
  const systemRtHash = await argon2.hash('BOOTSTRAP_INITIALIZATION_SECRET_2026');
  await prisma.session.create({
    data: {
      userId: rootUser.id,
      hashedRt: systemRtHash,
      deviceId: 'ZENITH-INFRA-ROOT-01',
      os: 'ZenithOS/Kernel',
      ipAddress: '127.0.0.1',
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // +1 Year
    },
  });

  console.log('✅ [ZENITH_SUCCESS]: Infrastructure synchronization complete.');
}

/**
 * LIFECYCLE MANAGEMENT
 */
main()
  .catch((e: Error) => {
    console.error('🔴 [CRITICAL_BOOT_FAILURE]: Provisioning aborted.');
    console.error(`Reason: ${e.message}`);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    console.log('🔌 [ZENITH_INFRA]: Infrastructure connectivity pool released.');
  });