import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { hasRole, ROLE_LABELS, ASSIGNABLE_ROLES, type Role } from "@/lib/rbac";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";

export default async function AdminUsersPage() {
  const session = await auth();
  if (!session?.user) redirect("/auth/login");

  const userRole = (session.user as any).role as string;
  if (!hasRole(userRole, "admin")) {
    return (
      <div className="p-8 text-center">
        <h1 className="text-2xl font-bold text-red-600">Хандах эрхгүй</h1>
        <p className="mt-2 text-gray-500">Энэ хуудас зөвхөн админ эрхтэй хэрэглэгчдэд зориулагдсан.</p>
      </div>
    );
  }

  const developers = await prisma.developer.findMany({
    orderBy: { createdAt: "desc" },
  });

  const assignableRoles = ASSIGNABLE_ROLES[userRole as Role] || [];

  async function updateRole(formData: FormData) {
    "use server";
    const targetId = formData.get("developerId") as string;
    const newRole = formData.get("role") as string;
    const sess = await auth();
    const currentRole = (sess?.user as any)?.role;

    if (!hasRole(currentRole, "admin")) return;
    if (newRole === "superadmin" && currentRole !== "superadmin") return;

    await prisma.developer.update({
      where: { id: targetId },
      data: { role: newRole },
    });
    revalidatePath("/dashboard/admin");
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Хэрэглэгчийн удирдлага</h1>
      <p className="text-sm text-gray-500 mb-4">
        Таны эрх: <span className="font-semibold text-green-600">{ROLE_LABELS[userRole as Role] || userRole}</span>
      </p>

      <div className="bg-white rounded-xl border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="text-left p-3 font-semibold">Нэр</th>
              <th className="text-left p-3 font-semibold">Sub</th>
              <th className="text-left p-3 font-semibold">Эрх</th>
              <th className="text-left p-3 font-semibold">Үйлдэл</th>
            </tr>
          </thead>
          <tbody>
            {developers.map((dev) => (
              <tr key={dev.id} className="border-t hover:bg-gray-50">
                <td className="p-3 font-medium">{dev.name || "—"}</td>
                <td className="p-3 text-gray-500 text-xs font-mono">{dev.sub.substring(0, 16)}...</td>
                <td className="p-3">
                  <RoleBadge role={dev.role} />
                </td>
                <td className="p-3">
                  {dev.role !== "superadmin" && assignableRoles.length > 0 ? (
                    <form action={updateRole} className="flex gap-2">
                      <input type="hidden" name="developerId" value={dev.id} />
                      <select name="role" defaultValue={dev.role} className="border rounded px-2 py-1 text-xs">
                        {[dev.role, ...assignableRoles.filter(r => r !== dev.role)].map((r) => (
                          <option key={r} value={r}>{ROLE_LABELS[r as Role] || r}</option>
                        ))}
                      </select>
                      <button type="submit" className="bg-blue-600 text-white px-3 py-1 rounded text-xs hover:bg-blue-700">
                        Хадгалах
                      </button>
                    </form>
                  ) : (
                    <span className="text-gray-400 text-xs">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RoleBadge({ role }: { role: string }) {
  const colors: Record<string, string> = {
    superadmin: "bg-red-100 text-red-700",
    admin: "bg-orange-100 text-orange-700",
    manager: "bg-blue-100 text-blue-700",
    user: "bg-gray-100 text-gray-700",
  };
  return (
    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${colors[role] || colors.user}`}>
      {ROLE_LABELS[role as Role] || role}
    </span>
  );
}
