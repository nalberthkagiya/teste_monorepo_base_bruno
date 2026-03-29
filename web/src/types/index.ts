import type { Role } from '@/generated/prisma';

export type AllowedRoutes = { 
  GET?: Role[]
  POST?: Role[]
  PATCH?: Role[]
  DELETE?: Role[]
}