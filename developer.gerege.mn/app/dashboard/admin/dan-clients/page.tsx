import { auth } from "@/lib/auth";
import { hasRole } from "@/lib/rbac";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";

export default async function DANClientsPage() {
  const session = await auth();
  if (!session?.user) redirect("/auth/login");
  if (!hasRole((session.user as any).role, "admin")) {
    return <div className="p-8 text-center text-red-600 font-bold">Хандах эрхгүй</div>;
  }

  const clients: any[] = await prisma.$queryRaw`
    SELECT id, name, callback_urls, active, created_at, updated_at FROM dan_clients ORDER BY created_at
  `;

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">DAN Gateway Clients</h1>
      <p className="text-sm text-gray-500 mb-4">dan.gerege.mn-д бүртгэлтэй KYC client-ууд</p>
      <div className="space-y-4">
        {clients.map((c) => (
          <div key={c.id} className="bg-white rounded-xl border p-5">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="font-bold text-lg">{c.name}</h3>
                <code className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">{c.id}</code>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${c.active ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
                {c.active ? "Идэвхтэй" : "Идэвхгүй"}
              </span>
            </div>
            <div className="text-sm">
              <div className="text-gray-500 text-xs mb-1">Callback URLs</div>
              <div className="space-y-1">
                {(c.callback_urls || []).map((url: string, i: number) => (
                  <div key={i} className="font-mono text-xs bg-gray-50 px-2 py-1 rounded truncate">{url}</div>
                ))}
              </div>
              <div className="text-gray-400 text-xs mt-3">
                Бүртгэсэн: {new Date(c.created_at).toLocaleDateString("mn-MN")} · Шинэчилсэн: {new Date(c.updated_at).toLocaleDateString("mn-MN")}
              </div>
            </div>
          </div>
        ))}
        {clients.length === 0 && (
          <div className="text-center py-12 text-gray-400">DAN client бүртгэлгүй байна</div>
        )}
      </div>
    </div>
  );
}
