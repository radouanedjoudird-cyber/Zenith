/*
  Warnings:

  - You are about to drop the column `metadata` on the `audit_logs` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "audit_logs" DROP COLUMN "metadata",
ADD COLUMN     "details" JSONB,
ADD COLUMN     "severity" TEXT NOT NULL DEFAULT 'INFO';

-- CreateIndex
CREATE INDEX "audit_logs_severity_idx" ON "audit_logs"("severity");
