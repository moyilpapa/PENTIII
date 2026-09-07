const BASE = "http://localhost:5050/api";

// The backend requires a shared API key on every /api/* route (see
// backend/security.py). Set it once per browser via localStorage:
//   localStorage.setItem("apiKey", "<the same value as API_KEY on the backend>")
// This is a local single-operator tool, so a prompt-once/localStorage key is
// an acceptable tradeoff -- it's not meant to gate multi-user access control.
function getApiKey() {
  try {
    return window.localStorage.getItem("apiKey") || "";
  } catch {
    return "";
  }
}

async function req(path, options = {}) {
  const apiKey = getApiKey();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(apiKey ? { "X-API-Key": apiKey } : {}),
    },
    ...options,
  });
  const isJson = res.headers.get("content-type")?.includes("application/json");
  const body = isJson ? await res.json() : null;
  if (!res.ok) {
    // `detail` carries the SSRF/validation guard's actual explanation
    // (e.g. which private IP a target resolved to); `hint` carries setup
    // instructions for auth-related failures. Surface whichever is present
    // instead of dropping it and showing only the generic `error` label.
    const extra = body?.detail ? ` ${body.detail}` : body?.hint ? ` ${body.hint}` : "";
    const message = `${body?.error || `Request failed (${res.status})`}.${extra}`;
    // Only a real 401 means *this client's* key is missing/wrong -- that's
    // the one case api.setApiKey() actually fixes. A 500 can be caused by
    // an unrelated backend crash (e.g. the SQLi engine), and even the one
    // 500 that IS auth-related ("server not configured") needs the
    // server's API_KEY env var set, not this client's localStorage key --
    // so suggesting api.setApiKey() there would send the user to fix the
    // wrong side of the connection.
    if (res.status === 401) {
      throw new Error(`${message} (Set it with api.setApiKey("..."))`);
    }
    throw new Error(message);
  }
  return body;
}

export const api = {
  setApiKey: (key) => {
    try {
      window.localStorage.setItem("apiKey", key);
    } catch {
      /* ignore */
    }
  },

  // targets
  listTargets: () => req("/targets"),
  createTarget: (name, url) =>
    req("/targets", { method: "POST", body: JSON.stringify({ name, url }) }),
  deleteTarget: (id) => req(`/targets/${id}`, { method: "DELETE" }),
  getScans: (id) => req(`/targets/${id}/scans`),

  // scans
  scanHttp: (id) => req(`/scan/http/${id}`, { method: "POST" }),
  scanEndpoints: (id) => req(`/scan/endpoints/${id}`, { method: "POST" }),
  scanJs: (id) => req(`/scan/js/${id}`, { method: "POST" }),
  scanSqli: (id, parameter) =>
    req(`/scan/sqli/${id}`, { method: "POST", body: JSON.stringify({ parameter }) }),

  // Pent III advancement
  collectEndpoints: (id) => req(`/scan/collect/${id}`, { method: "POST" }),
  scanSqliAdvanced: (id, payload) =>
    req(`/scan/sqli-advanced/${id}`, { method: "POST", body: JSON.stringify(payload) }),
  scanSqlmap: (id, payload) =>
    req(`/scan/sqli-sqlmap/${id}`, { method: "POST", body: JSON.stringify(payload) }),

  // findings
  listFindings: (targetId) => req(`/findings/${targetId}`),
  listAutoFindings: (targetId) => req(`/findings/${targetId}/auto`),
  createFinding: (finding) =>
    req("/findings", { method: "POST", body: JSON.stringify(finding) }),
  updateFinding: (id, fields) =>
    req(`/findings/${id}`, { method: "PATCH", body: JSON.stringify(fields) }),
  deleteFinding: (id) => req(`/findings/${id}`, { method: "DELETE" }),

  // report
  getReport: (targetId, mode = "manual") => req(`/report/${targetId}?mode=${mode}`),

  health: () => req("/health"),
};
