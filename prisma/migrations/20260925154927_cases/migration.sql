-- CreateEnum
CREATE TYPE "CaseStatus" AS ENUM ('OPEN', 'CLOSED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "CaseItemKind" AS ENUM ('NOTE', 'EVIDENCE', 'CUSTODY', 'EVENT', 'LINK');

-- CreateTable
CREATE TABLE "Case" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "status" "CaseStatus" NOT NULL DEFAULT 'OPEN',
    "severity" TEXT,
    "tags" JSONB,

    CONSTRAINT "Case_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CaseItem" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "kind" "CaseItemKind" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "author" TEXT NOT NULL DEFAULT 'operator',
    "data" JSONB NOT NULL,

    CONSTRAINT "CaseItem_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Case_status_updatedAt_idx" ON "Case"("status", "updatedAt");

-- CreateIndex
CREATE INDEX "CaseItem_caseId_createdAt_idx" ON "CaseItem"("caseId", "createdAt");

-- AddForeignKey
ALTER TABLE "CaseItem" ADD CONSTRAINT "CaseItem_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "Case"("id") ON DELETE CASCADE ON UPDATE CASCADE;
