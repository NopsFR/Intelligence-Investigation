-- v2 intelligence engine: JSONB payloads, richer findings, typed graph edges,
-- provider cache, shared rate-limit buckets and provider check history.
-- Existing rows are preserved: TEXT JSON columns are cast to JSONB (invalid
-- payloads become NULL rather than aborting the migration).

CREATE OR REPLACE FUNCTION pg_temp.nops_try_jsonb(input TEXT) RETURNS JSONB AS $$
BEGIN
  IF input IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN input::jsonb;
EXCEPTION WHEN others THEN
  RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Enums
ALTER TYPE "ObservableType" ADD VALUE IF NOT EXISTS 'EMAIL';
ALTER TYPE "ObservableType" ADD VALUE IF NOT EXISTS 'CERT_SHA256';
ALTER TYPE "ProviderStatus" ADD VALUE IF NOT EXISTS 'SKIPPED';

-- Investigation
ALTER TABLE "Investigation"
  ADD COLUMN "completedAt" TIMESTAMP(3),
  ADD COLUMN "durationMs" INTEGER,
  ADD COLUMN "plan" JSONB,
  ADD COLUMN "previousId" TEXT;
ALTER TABLE "Investigation"
  ALTER COLUMN "metadata" TYPE JSONB USING pg_temp.nops_try_jsonb("metadata");
UPDATE "Investigation" SET "completedAt" = "updatedAt" WHERE "status" IN ('COMPLETE', 'PARTIAL', 'FAILED');
DROP INDEX IF EXISTS "Investigation_normalizedObservable_idx";
CREATE INDEX "Investigation_normalizedObservable_createdAt_idx" ON "Investigation"("normalizedObservable", "createdAt");
CREATE INDEX "Investigation_status_idx" ON "Investigation"("status");

-- ProviderResult
ALTER TABLE "ProviderResult" RENAME COLUMN "normalized" TO "result";
ALTER TABLE "ProviderResult"
  ALTER COLUMN "result" TYPE JSONB USING pg_temp.nops_try_jsonb("result"),
  ALTER COLUMN "raw" TYPE JSONB USING pg_temp.nops_try_jsonb("raw"),
  ADD COLUMN "cached" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "diagnostics" JSONB,
  ADD COLUMN "httpStatus" INTEGER,
  ADD COLUMN "startedAt" TIMESTAMP(3);
DROP INDEX IF EXISTS "ProviderResult_investigationId_idx";
DROP INDEX IF EXISTS "ProviderResult_provider_idx";
CREATE UNIQUE INDEX "ProviderResult_investigationId_provider_key" ON "ProviderResult"("investigationId", "provider");
CREATE INDEX "ProviderResult_provider_retrievedAt_idx" ON "ProviderResult"("provider", "retrievedAt");

-- Finding
ALTER TABLE "Finding"
  ADD COLUMN "rule" TEXT NOT NULL DEFAULT 'legacy',
  ADD COLUMN "rationale" TEXT,
  ADD COLUMN "evidenceData" JSONB,
  ADD COLUMN "observable" TEXT,
  ADD COLUMN "remediation" TEXT,
  ADD COLUMN "references" JSONB;
UPDATE "Finding" SET "rationale" = "methodology" WHERE "methodology" IS NOT NULL;
ALTER TABLE "Finding" DROP COLUMN "methodology";
ALTER TABLE "Finding" ALTER COLUMN "rule" DROP DEFAULT;
DROP INDEX IF EXISTS "Finding_severity_idx";
CREATE INDEX "Finding_severity_observedAt_idx" ON "Finding"("severity", "observedAt");

-- Relationship: typed endpoints for the evidence graph
ALTER TABLE "Relationship" RENAME COLUMN "sourceNode" TO "sourceValue";
ALTER TABLE "Relationship" RENAME COLUMN "targetNode" TO "targetValue";
ALTER TABLE "Relationship" RENAME COLUMN "sourceProvider" TO "provider";
ALTER TABLE "Relationship"
  ADD COLUMN "sourceType" TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN "targetType" TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN "targetLabel" TEXT;
ALTER TABLE "Relationship" ALTER COLUMN "sourceType" DROP DEFAULT;
ALTER TABLE "Relationship" ALTER COLUMN "targetType" DROP DEFAULT;

-- JSON arrays stored as TEXT previously
ALTER TABLE "IocEntry"
  ALTER COLUMN "tags" TYPE JSONB USING pg_temp.nops_try_jsonb("tags"),
  ALTER COLUMN "investigationRefIds" TYPE JSONB USING pg_temp.nops_try_jsonb("investigationRefIds");
CREATE INDEX "IocEntry_updatedAt_idx" ON "IocEntry"("updatedAt");
ALTER TABLE "Observable"
  ALTER COLUMN "tags" TYPE JSONB USING pg_temp.nops_try_jsonb("tags");

ALTER TABLE "ApiProviderHealth" ADD COLUMN "lastErrorType" TEXT;

-- New tables
CREATE TABLE "ProviderCheck" (
    "id" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "checkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" TEXT NOT NULL,
    "latencyMs" INTEGER,
    "errorType" TEXT,
    "message" TEXT,
    CONSTRAINT "ProviderCheck_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "ProviderCheck_provider_checkedAt_idx" ON "ProviderCheck"("provider", "checkedAt");

CREATE TABLE "ProviderCache" (
    "id" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "cacheKey" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "result" JSONB,
    "raw" JSONB,
    "diagnostics" JSONB,
    "httpStatus" INTEGER,
    "latencyMs" INTEGER,
    "retrievedAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ProviderCache_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "ProviderCache_provider_cacheKey_key" ON "ProviderCache"("provider", "cacheKey");
CREATE INDEX "ProviderCache_expiresAt_idx" ON "ProviderCache"("expiresAt");

CREATE TABLE "RateLimitBucket" (
    "key" TEXT NOT NULL,
    "windowStart" TIMESTAMP(3) NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 0,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "RateLimitBucket_pkey" PRIMARY KEY ("key", "windowStart")
);
CREATE INDEX "RateLimitBucket_expiresAt_idx" ON "RateLimitBucket"("expiresAt");
