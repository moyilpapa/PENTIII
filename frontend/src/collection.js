// Mirrors backend/scanner.py's collect_endpoints(): merges Endpoint Discovery +
// JavaScript Analysis results into one normalized, deduplicated, same-host
// list with query parameters detected. Built client-side (from results already
// fetched during a full scan) so it never issues an extra round of requests
// to the target just to compute the merge.
export function buildCollection(targetUrl, endpointResult, jsResult) {
  const href = /^https?:\/\//i.test(targetUrl) ? targetUrl : `http://${targetUrl}`;
  let base;
  try {
    base = new URL(href);
  } catch {
    return { ok: false, base_url: href, total_endpoints: 0, parameterized_endpoints: 0, endpoints: [] };
  }

  const seen = new Map();
  const add = (raw, source) => {
    if (!raw) return;
    let u;
    try {
      u = new URL(raw, base);
    } catch {
      return;
    }
    if (u.host !== base.host) return; // same-host only, matches backend scope
    const norm = u.toString();
    const params = [...u.searchParams.keys()];
    if (seen.has(norm)) {
      const entry = seen.get(norm);
      if (!entry.sources.includes(source)) entry.sources.push(source);
    } else {
      seen.set(norm, { url: norm, sources: [source], parameters: params, has_parameters: params.length > 0 });
    }
  };

  for (const r of endpointResult?.all_results || []) {
    if (r.exists && r.url) add(r.url, "endpoint_discovery");
  }
  for (const e of jsResult?.unique_endpoints || []) {
    add(e, "javascript_analysis");
  }

  const all = [...seen.values()].sort((a, b) => a.url.localeCompare(b.url));
  const parameterized = all.filter((e) => e.has_parameters);

  return {
    ok: true,
    base_url: base.toString(),
    total_endpoints: all.length,
    parameterized_endpoints: parameterized.length,
    endpoints: all,
  };
}
