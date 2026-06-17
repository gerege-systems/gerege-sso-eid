import { auth } from "@/lib/auth";
import { hasRole } from "@/lib/rbac";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";

export default async function SSOClientsPage() {
  const session = await auth();
  if (!session?.user) redirect("/auth/login");
  if (!hasRole((session.user as any).role, "admin")) {
    return <div className="p-8 text-center text-red-600 font-bold">Хандах эрхгүй</div>;
  }

  const clients: any[] = await prisma.$queryRaw`
    SELECT id, name, redirect_uris, scopes, is_active, created_at FROM sso_clients ORDER BY created_at
  `;

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">SSO Clients</h1>
      <p className="text-sm text-gray-500 mb-4">sso.gerege.mn-д бүртгэлтэй OIDC client-ууд</p>
      <div className="space-y-4">
        {clients.map((c) => (
          <div key={c.id} className="bg-white rounded-xl border p-5">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="font-bold text-lg">{c.name}</h3>
                <code className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">{c.id}</code>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${c.is_active ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
                {c.is_active ? "Идэвхтэй" : "Идэвхгүй"}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
              <div>
                <div className="text-gray-500 text-xs mb-1">Redirect URIs</div>
                <div className="space-y-1">
                  {(c.redirect_uris || []).map((uri: string, i: number) => (
                    <div key={i} className="font-mono text-xs bg-gray-50 px-2 py-1 rounded truncate">{uri}</div>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-gray-500 text-xs mb-1">Scopes</div>
                <div className="flex flex-wrap gap-1">
                  {(c.scopes || []).map((s: string) => (
                    <span key={s} className="bg-blue-50 text-blue-700 px-2 py-0.5 rounded text-xs font-medium">{s}</span>
                  ))}
                </div>
                <div className="text-gray-400 text-xs mt-2">
                  {new Date(c.created_at).toLocaleDateString("mn-MN")}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
