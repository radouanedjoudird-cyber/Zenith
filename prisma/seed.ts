/**
 * ZENITH SYSTEMS - CORE IDENTITY SEEDING ENGINE
 * --------------------------------------------
 * Description: Initializes the system with the primary Administrative identity.
 * Standards: 
 * - Bcrypt hashing with 12 rounds for high-entropy security.
 * - Idempotent execution (prevents duplicate entries).
 * - Full compliance with Prisma Schema requirements.
 * * @author Radouane Djoudi
 * @version 1.1.0
 */

import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🚀 [ZENITH_SEED]: Initialization of system identity deployment...');

  // Configuration for the Super Admin
  // Note: These should ideally be moved to .env for production environments
  const adminEmail = 'admin@zenith-systems.dz';
  const adminPassword = 'Zenith@2026!SecureAdmin'; 

  // Check if the identity already exists to ensure the script is idempotent
  const existingAdmin = await prisma.user.findUnique({
    where: { email: adminEmail },
  });

  if (!existingAdmin) {
    // Applying security logic consistent with AuthService
    const hashedPassword = await bcrypt.hash(adminPassword, 12);
    
    await prisma.user.create({
      data: {
        email: adminEmail,
        password: hashedPassword,
        firstName: 'System',
        familyName: 'Admin',
        phoneNumber: '+213000000000', // Mandatory as per Zenith Schema
        role: Role.ADMIN,            // Elevation to Administrative privileges
      },
    });

    console.log(`✅ [ZENITH_SEED]: Super Admin identity successfully deployed: ${adminEmail}`);
  } else {
    console.log('ℹ️ [ZENITH_SEED]: Administrative identity already exists. Skipping deployment.');
  }
}

/**
 * Execution Wrapper
 * Handles process lifecycle and resource cleanup.
 */
main()
  .catch((error) => {
    console.error('❌ [ZENITH_SEED_ERROR]: Critical failure during identity seeding:');
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    // Terminate Prisma connection to prevent dangling database clients
    await prisma.$disconnect();
    console.log('🔌 [ZENITH_SEED]: Database connection closed.');
  });