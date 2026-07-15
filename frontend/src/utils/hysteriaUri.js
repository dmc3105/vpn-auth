const HYSTERIA_URI_TAG = import.meta.env.VITE_HYSTERIA_URI_TAG || "VPN Auth";

export function parseServerEndpoint(rawServer) {
  const input = String(rawServer || "").trim();
  if (!input) return { host: "", port: 443 };

  const withScheme = input.includes("://") ? input : `https://${input}`;
  try {
    const url = new URL(withScheme);
    return {
      host: url.hostname,
      port: Number(url.port) || 443
    };
  } catch {
    const cleaned = input.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    const [host, portRaw] = cleaned.split(":");
    return { host: host || cleaned, port: Number(portRaw) || 443 };
  }
}

export function buildHysteriaUri(connectionData) {
  const server = String(connectionData?.server || "").trim();
  const username = String(connectionData?.username || connectionData?.vpn_username || "").trim();
  const password = String(connectionData?.password || "").trim();
  const { host, port } = parseServerEndpoint(server);
  const auth = encodeURIComponent(`${username}:${password}`);
  const sni = encodeURIComponent(host || server);
  const tag = encodeURIComponent(HYSTERIA_URI_TAG);
  return `hysteria2://${auth}@${host || server}:${port}?sni=${sni}#${tag}`;
}
