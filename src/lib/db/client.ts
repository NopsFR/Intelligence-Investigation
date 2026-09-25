import "server-only";
import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

export const prisma = globalForPrisma.prisma ?? new PrismaClient({ log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"] });

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;

/** JSON columns: Prisma wants undefined (not null) to leave a column empty. */
export function json<T>(value: T | null | undefined): T | undefined {
  return value === null ? undefined : value;
}
