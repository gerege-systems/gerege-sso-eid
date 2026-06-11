"use client";

import { useState } from "react";

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Clipboard API unavailable (e.g. non-HTTPS) — fall back to manual select
      const ok = window.prompt("Гараар хуулна уу:", value);
      void ok;
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div>
      <label className="block text-xs font-medium text-slate-400 mb-1.5">{label}</label>
      <div className="flex items-stretch gap-2">
        <code className="flex-1 min-w-0 px-3 py-2.5 bg-black/30 border border-white/10 rounded-lg text-xs text-slate-200 font-mono break-all">
          {value}
        </code>
        <button
          type="button"
          onClick={copy}
          className="shrink-0 px-3 py-2.5 bg-white/[0.06] hover:bg-white/[0.1] border border-white/10 rounded-lg text-xs font-semibold text-white transition-all"
        >
          {copied ? "Хуулсан ✓" : "Хуулах"}
        </button>
      </div>
    </div>
  );
}

export default function SecretReveal({
  id,
  secret,
  name,
  hmacKey,
  regenerated,
}: {
  id: string;
  secret: string;
  name?: string;
  hmacKey?: string;
  regenerated?: boolean;
}) {
  return (
    <div className="space-y-5">
      <div className="bg-amber-500/10 border border-amber-500/25 rounded-xl px-4 py-3">
        <p className="text-sm text-amber-300 font-medium leading-relaxed">
          ⚠{" "}
          {regenerated
            ? "Secret шинэчлэгдлээ. Хуучин secret хүчингүй боллоо."
            : `"${name}" client үүслээ.`}{" "}
          Доорх мэдээллийг одоо хадгалж авна уу — дахин харагдахгүй.
        </p>
      </div>

      <CopyField label="Client ID" value={id} />
      <CopyField label="Client Secret" value={secret} />
      {hmacKey ? <CopyField label="HMAC Key" value={hmacKey} /> : null}

      <a
        href="/admin"
        className="inline-block mt-2 px-5 py-2.5 bg-primary hover:bg-primary-light text-white font-bold text-sm rounded-xl transition-all"
      >
        Дууссан — Admin руу буцах
      </a>
    </div>
  );
}
