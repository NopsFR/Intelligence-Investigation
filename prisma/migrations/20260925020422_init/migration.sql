-- CreateTable
CREATE TABLE "Investigation" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "observable" TEXT NOT NULL,
    "observableType" TEXT NOT NULL,
    "normalizedObservable" TEXT NOT NULL,
    "mode" TEXT NOT NULL DEFAULT 'QUICK',
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "summary" TEXT,
    "metadata" TEXT
);

-- CreateTable
CREATE TABLE "ProviderResult" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "investigationId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "latencyMs" INTEGER,
    "retrievedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "errorType" TEXT,
    "errorMessage" TEXT,
    "normalized" TEXT,
    "raw" TEXT,
    CONSTRAINT "ProviderResult_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "Investigation" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "investigationId" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "evidence" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "observedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confidence" TEXT,
    "methodology" TEXT,
    CONSTRAINT "Finding_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "Investigation" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Observable" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "value" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL,
    "tags" TEXT
);

-- CreateTable
CREATE TABLE "Relationship" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "investigationId" TEXT NOT NULL,
    "sourceNode" TEXT NOT NULL,
    "targetNode" TEXT NOT NULL,
    "relationType" TEXT NOT NULL,
    "sourceProvider" TEXT NOT NULL,
    "evidence" TEXT NOT NULL,
    "observedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Relationship_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "Investigation" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "IocEntry" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "value" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "tags" TEXT,
    "notes" TEXT,
    "source" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "investigationRefIds" TEXT
);

-- CreateTable
CREATE TABLE "ApiProviderHealth" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "provider" TEXT NOT NULL,
    "configured" BOOLEAN NOT NULL DEFAULT false,
    "lastCheckedAt" DATETIME,
    "lastStatus" TEXT,
    "lastLatencyMs" INTEGER,
    "lastError" TEXT
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
