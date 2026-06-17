import { auth } from "@/lib/auth";
import { redirect } from "next/navigation";
import Link from "next/link";
import { hasRole } from "@/lib/rbac";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();
  if (!session?.user) redirect("/auth/login");

  const role = (session.user as any).role as string | undefined;

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 flex gap-8">
      <aside className="hidden md:block w-48 flex-shrink-0">
        <nav className="space-y-1 sticky top-20">
          <SideLink href="/dashboard">Тойм</SideLink>
          <SideLink href="/dashboard/apps">Apps</SideLink>
          <SideLink href="/dashboard/tenants">Tenants</SideLink>
          <SideLink href="/dashboard/settings">Тохиргоо</SideLink>
          {hasRole(role, "admin") && (
            <div className="pt-4 border-t border-white/10 mt-4">
              <div className="px-3 py-1 text-xs text-slate-500 uppercase tracking-wider">Админ</div>
              <SideLink href="/dashboard/admin">Хэрэглэгчид</SideLink>
              <SideLink href="/dashboard/admin/clients">SSO Clients</SideLink>
              <SideLink href="/dashboard/admin/dan-clients">DAN Clients</SideLink>
            </div>
          )}
          <div className="pt-4 border-t border-white/10 mt-4">
            <SideLink href="/docs">Docs</SideLink>
            <SideLink href="/docs/api-reference">API Reference</SideLink>
          </div>
        </nav>
      </aside>
      <main className="flex-1 min-w-0">{children}</main>
    </div>
  );
}

function SideLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      className="block px-3 py-2 text-sm text-slate-400 rounded-lg hover:bg-white/5 hover:text-white transition-colors"
    >
      {children}
    </Link>
  );
}
