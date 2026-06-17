export type Role = "superadmin" | "admin" | "manager" | "user";

const ROLE_HIERARCHY: Record<Role, number> = {
  superadmin: 4,
  admin: 3,
  manager: 2,
  user: 1,
};

export function hasRole(userRole: string | undefined, requiredRole: Role): boolean {
  if (!userRole) return false;
  const userLevel = ROLE_HIERARCHY[userRole as Role] || 0;
  const requiredLevel = ROLE_HIERARCHY[requiredRole] || 0;
  return userLevel >= requiredLevel;
}

export function canManageUsers(role: string | undefined): boolean {
  return hasRole(role, "admin");
}

export function canManageTenants(role: string | undefined): boolean {
  return hasRole(role, "manager");
}

export function isSuperAdmin(role: string | undefined): boolean {
  return role === "superadmin";
}

export const ROLE_LABELS: Record<Role, string> = {
  superadmin: "Супер админ",
  admin: "Админ",
  manager: "Менежер",
  user: "Хэрэглэгч",
};

export const ASSIGNABLE_ROLES: Record<Role, Role[]> = {
  superadmin: ["admin", "manager", "user"],
  admin: ["manager", "user"],
  manager: ["user"],
  user: [],
};
