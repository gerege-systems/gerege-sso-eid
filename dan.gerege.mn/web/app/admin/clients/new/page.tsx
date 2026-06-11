import { redirect } from "next/navigation";
import { createDANClient } from "@/lib/api";
import SecretReveal from "../SecretReveal";

export default function NewClientPage({
  searchParams,
}: {
  searchParams: {
    id?: string;
    secret?: string;
    hmac_key?: string;
    name?: string;
    regenerated?: string;
  };
}) {
  // After create (or secret regenerate) we redirect back here with the secret
  // in the query string and show it once — it is never retrievable again.
  if (searchParams.secret && searchParams.id) {
    return (
      <div className="max-w-lg mx-auto px-6 py-10">
        <h1 className="text-2xl font-bold text-white mb-2">
          {searchParams.regenerated ? "Шинэ Secret" : "Client үүслээ"}
        </h1>
        <p className="text-sm text-slate-400 mb-8">
          Энэ мэдээллийг хаалттай газар хадгална уу. Дахин харах боломжгүй.
        </p>
        <SecretReveal
          id={searchParams.id}
          secret={searchParams.secret}
          name={searchParams.name}
          hmacKey={searchParams.hmac_key}
          regenerated={Boolean(searchParams.regenerated)}
        />
      </div>
    );
  }

  async function handleCreate(formData: FormData) {
    "use server";

    const name = formData.get("name") as string;
    const urls = (formData.get("callback_urls") as string)
      .split("\n")
      .map((u) => u.trim())
      .filter(Boolean);

    if (!name || urls.length === 0) {
      throw new Error("name and callback_urls required");
    }

    const result = await createDANClient({ name, callback_urls: urls });

    // Pass the one-time secret via query params to the reveal screen above
    const params = new URLSearchParams({
      id: result.id,
      secret: result.secret,
      hmac_key: result.hmac_key,
      name: result.name,
    });
    redirect(`/admin/clients/new?${params.toString()}`);
  }

  return (
    <div className="max-w-lg mx-auto px-6 py-10">
      <h1 className="text-2xl font-bold text-white mb-2">Шинэ DAN Client</h1>
      <p className="text-sm text-slate-400 mb-8">
        DAN verify ашиглах шинэ client бүртгэх
      </p>

      <form action={handleCreate} className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1.5">
            Нэр
          </label>
          <input
            name="name"
            required
            placeholder="Миний апп"
            className="w-full px-4 py-2.5 bg-white/[0.05] border border-white/10 rounded-xl text-white text-sm focus:outline-none focus:border-primary"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1.5">
            Callback URLs (мөр бүрт нэг)
          </label>
          <textarea
            name="callback_urls"
            required
            rows={3}
            placeholder={"https://myapp.mn/api/dan/callback"}
            className="w-full px-4 py-2.5 bg-white/[0.05] border border-white/10 rounded-xl text-white text-sm font-mono focus:outline-none focus:border-primary"
          />
          <p className="text-xs text-slate-500 mt-1">
            Зөвхөн HTTPS URL зөвшөөрөгдөнө
          </p>
        </div>

        <button
          type="submit"
          className="w-full py-3 bg-primary hover:bg-primary-light text-white font-bold rounded-xl transition-all"
        >
          Client үүсгэх
        </button>
      </form>

      <div className="mt-6">
        <a href="/admin" className="text-sm text-slate-400 hover:text-white">
          &larr; Admin руу буцах
        </a>
      </div>
    </div>
  );
}
