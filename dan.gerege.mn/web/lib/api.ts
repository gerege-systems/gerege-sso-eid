const DAN_API_URL = process.env.DAN_API_URL || "http://dan-api:8444";
const DAN_ADMIN_KEY = process.env.DAN_ADMIN_KEY || "";

async function danFetch(path: string, options: RequestInit = {}) {
  const res = await fetch(`${DAN_API_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${DAN_ADMIN_KEY}`,
      ...options.headers,
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`DAN API error ${res.status}: ${body}`);
  }
  return res.json();
}

export async function listDANClients() {
  return danFetch("/api/clients");
}

export async function createDANClient(data: {
  name: string;
  callback_urls: string[];
}) {
  return danFetch("/api/clients", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function regenerateDANClientSecret(id: string) {
  return danFetch(`/api/clients/${id}/secret`, {
    method: "POST",
  });
}

export async function deactivateDANClient(id: string) {
  return danFetch(`/api/clients/${id}`, {
    method: "DELETE",
  });
}
