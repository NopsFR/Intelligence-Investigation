-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "ObservableType" AS ENUM ('IPV4', 'IPV6', 'DOMAIN', 'URL', 'MD5', 'SHA1', 'SHA256', 'CVE', 'ASN');

-- CreateEnum
CREATE TYPE "InvestigationStatus" AS ENUM ('PENDING', 'RUNNING', 'COMPLETE', 'PARTIAL', 'FAILED');

-- CreateEnum
CREATE TYPE "ProviderStatus" AS ENUM ('SUCCESS', 'PARTIAL', 'EMPTY', 'NOT_CONFIGURED', 'RATE_LIMITED', 'AUTH_FAILED', 'TIMEOUT', 'NETWORK_ERROR', 'INVALID_RESPONSE', 'UNAVAILABLE');

-- CreateEnum
CREATE TYPE "InvestigationMode" AS ENUM ('QUICK', 'DEEP');

-- CreateTable
CREATE TABLE "Investigation" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "observable" TEXT NOT NULL,
    "observableType" "ObservableType" NOT NULL,
    "normalizedObservable" TEXT NOT NULL,
    "mode" "InvestigationMode" NOT NULL DEFAULT 'QUICK',
    "status" "InvestigationStatus" NOT NULL DEFAULT 'PENDING',
    "summary" TEXT,
    "metadata" TEXT,

    CONSTRAINT "Investigation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProviderResult" (
    "id" TEXT NOT NULL,
    "investigationId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "status" "ProviderStatus" NOT NULL,
    "latencyMs" INTEGER,
    "retrievedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "errorType" TEXT,
    "errorMessage" TEXT,
    "normalized" TEXT,
    "raw" TEXT,

    CONSTRAINT "ProviderResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "investigationId" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "evidence" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confidence" TEXT,
    "methodology" TEXT,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Observable" (
    "id" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "type" "ObservableType" NOT NULL,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,
    "tags" TEXT,

    CONSTRAINT "Observable_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Relationship" (
    "id" TEXT NOT NULL,
    "investigationId" TEXT NOT NULL,
    "sourceNode" TEXT NOT NULL,
    "targetNode" TEXT NOT NULL,
    "relationType" TEXT NOT NULL,
    "sourceProvider" TEXT NOT NULL,
    "evidence" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Relationship_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IocEntry" (
    "id" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "type" "ObservableType" NOT NULL,
    "tags" TEXT,
    "notes" TEXT,
    "source" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "investigationRefIds" TEXT,

    CONSTRAINT "IocEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiProviderHealth" (
    "id" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "configured" BOOLEAN NOT NULL DEFAULT false,
    "lastCheckedAt" TIMESTAMP(3),
    "lastStatus" TEXT,
    "lastLatencyMs" INTEGER,
    "lastError" TEXT,

    CONSTRAINT "ApiProviderHealth_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Investigation_normalizedObservable_idx" ON "Investigation"("normalizedObservable");

-- CreateIndex
CREATE INDEX "Investigation_observableType_idx" ON "Investigation"("observableType");

-- CreateIndex
CREATE INDEX "Investigation_createdAt_idx" ON "Investigation"("createdAt");

-- CreateIndex
CREATE INDEX "ProviderResult_investigationId_idx" ON "ProviderResult"("investigationId");

-- CreateIndex
CREATE INDEX "ProviderResult_provider_idx" ON "ProviderResult"("provider");

-- CreateIndex
CREATE INDEX "Finding_investigationId_idx" ON "Finding"("investigationId");

-- CreateIndex
CREATE INDEX "Finding_severity_idx" ON "Finding"("severity");

-- CreateIndex
CREATE UNIQUE INDEX "Observable_value_type_key" ON "Observable"("value", "type");

-- CreateIndex
CREATE INDEX "Relationship_investigationId_idx" ON "Relationship"("investigationId");

-- CreateIndex
CREATE UNIQUE INDEX "IocEntry_value_type_key" ON "IocEntry"("value", "type");

-- CreateIndex
CREATE UNIQUE INDEX "ApiProviderHealth_provider_key" ON "ApiProviderHealth"("provider");

-- AddForeignKey
ALTER TABLE "ProviderResult" ADD CONSTRAINT "ProviderResult_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "Investigation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "Investigation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Relationship" ADD CONSTRAINT "Relationship_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "Investigation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

