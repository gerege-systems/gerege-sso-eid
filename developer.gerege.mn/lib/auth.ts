import NextAuth from "next-auth";
import { prisma } from "./db";

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    {
      id: "gerege-sso",
      name: "GeregeID",
      type: "oidc",
      issuer: process.env.NEXT_PUBLIC_SSO_URL || "https://sso.gerege.mn",
      clientId: process.env.EID_CLIENT_ID!,
      clientSecret: process.env.EID_CLIENT_SECRET!,
      authorization: { params: { scope: "openid profile" } },
    },
  ],
  callbacks: {
    async jwt({ token, profile }) {
      if (profile) {
        token.sub = profile.sub as string;
        token.certSerial = (profile as any).cert_serial || "";
        token.givenName = (profile as any).given_name || "";
        token.familyName = (profile as any).family_name || "";
        token.name = (profile as any).name || "";
        token.tenantId = (profile as any).tenant_id || "";
        token.tenantRole = (profile as any).tenant_role || "";
        token.ial = (profile as any).identity_assurance_level || "";

        // Upsert developer
        const dev = await prisma.developer.upsert({
          where: { sub: token.sub! },
          update: {
            name: token.name || "",
            givenName: token.givenName as string,
            familyName: token.familyName as string,
            certSerial: token.certSerial as string,
          },
          create: {
            sub: token.sub!,
            name: token.name || "",
            givenName: token.givenName as string || "",
            familyName: token.familyName as string || "",
            certSerial: token.certSerial as string || "",
            role: "user",
          },
        });
        token.role = dev.role;
        token.developerId = dev.id;
      }

      // Refresh role on each request if not set
      if (!token.role && token.sub) {
        const dev = await prisma.developer.findUnique({ where: { sub: token.sub } });
        if (dev) {
          token.role = dev.role;
          token.developerId = dev.id;
        }
      }

      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        (session.user as any).sub = token.sub;
        (session.user as any).certSerial = token.certSerial;
        (session.user as any).tenantId = token.tenantId;
        (session.user as any).tenantRole = token.tenantRole;
        (session.user as any).ial = token.ial;
        (session.user as any).developerId = token.developerId;
        (session.user as any).role = token.role;
      }
      return session;
    },
  },
  pages: {
    signIn: "/auth/login",
  },
  trustHost: true,
});
