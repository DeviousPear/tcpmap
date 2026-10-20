import { reverse } from "node:dns/promises";
import html from "./index.html" with { type: "text" };

const proc = Bun.spawn(["sudo", "tcpdump", "-n", "-l", "-q"], {
  stdout: "pipe",
  stderr: "pipe",
});

const clients = new Set();
const encoder = new TextEncoder();
const seen = new Set();
const cache = new Map(); // ip -> enriched payload

function send(controller, payload) {
  const msg = `data: ${JSON.stringify(payload)}\n\n`;
  try {
    controller.enqueue(encoder.encode(msg));
  } catch {
    clients.delete(controller);
  }
}

function broadcast(payload) {
  for (const c of clients) send(c, payload);
}

function isPublicIp(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n) || n < 0 || n > 255)) return false;
  if (p[0] === 10) return false;
  if (p[0] === 127) return false;
  if (p[0] === 169 && p[1] === 254) return false;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
  if (p[0] === 192 && p[1] === 168) return false;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return false;
  if (p[0] >= 224) return false; // multicast/reserved/broadcast
  if (ip === '255.255.255.255' || ip === '0.0.0.0') return false;
  return true;
}

function serviceForPort(port) {
  const map = {
    20: "FTP (data)", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    123: "NTP", 135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "SMB (NetBIOS)",
    143: "IMAP", 161: "SNMP", 162: "SNMP Trap", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 500: "IKE (IPsec)", 514: "Syslog", 554: "RTSP",
    587: "SMTP (submission)", 631: "IPP (printing)", 636: "LDAPS", 853: "DNS over TLS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1434: "MSSQL Browser", 1521: "Oracle DB", 1883: "MQTT", 1900: "SSDP (UPnP)",
    2049: "NFS", 2181: "Zookeeper", 2375: "Docker", 2376: "Docker (TLS)", 2456: "Valheim",
    3000: "Dev server", 3306: "MySQL", 3389: "RDP", 3478: "STUN/TURN", 4444: "Metasploit/adb",
    4500: "IPsec NAT-T", 5000: "Flask/UPnP", 5060: "SIP", 5222: "XMPP", 5353: "mDNS",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes API",
    6667: "IRC", 6881: "BitTorrent", 7777: "Terraria", 8000: "HTTP alt", 8080: "HTTP alt",
    8443: "HTTPS alt", 8888: "HTTP alt", 9000: "SonarQube/PHP-FPM", 9090: "Prometheus",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch", 10250: "Kubelet",
    11211: "Memcached", 19132: "Minecraft (Bedrock)", 24444: "Netdata", 25565: "Minecraft",
    27015: "Source Engine (CS)", 27017: "MongoDB", 51820: "WireGuard",
  };
  if (port == null) return null;
  if (map[port]) return map[port];
  // BitTorrent range
  if (port >= 6881 && port <= 6889) return "BitTorrent";
  return null;
}

async function enrich(ip, connection, port) {
  if (!isPublicIp(ip)) {
    const payload = { ip, connection: connection || null, port: port || null, service: serviceForPort(port) };
    cache.set(ip, payload);
    broadcast(payload);
    return payload;
  }
  let hostname = null;
  try {
    const names = await reverse(ip);
    hostname = names && names.length ? names[0] : null;
  } catch {}

  let geo = null;
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}`);
    geo = await res.json();
    if (!geo || geo.status !== "success") geo = null;
  } catch {}

  const payload = {
    ip,
    connection: connection || null,
    port: port || null,
    hostname,
    ...(geo
      ? {
          lat: geo.lat,
          lon: geo.lon,
          city: geo.city,
          region: geo.regionName,
          country: geo.country,
          countryCode: geo.countryCode,
          zip: geo.zip,
          timezone: geo.timezone,
          isp: geo.isp,
          org: geo.org,
          as: geo.as,
          service: serviceForPort(port),
        }
      : {}),
  };
  cache.set(ip, payload);
  broadcast(payload);
  return payload;
}

// Consume tcpdump output, extract IPs via regex, enrich + broadcast new ones over SSE.
(async () => {
  const reader = proc.stdout.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  const ipRegex = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      const portMatch = line.match(/>\s+[^\s]+\.(\d+):/);
      const dstPort = portMatch ? parseInt(portMatch[1], 10) : null;
      let connection = null;
      if (/\bUDP\b/i.test(line)) {
        connection = (dstPort === 443 || dstPort === 853) ? "QUIC" : "UDP";
      } else if (/\btcp\b/i.test(line)) {
        if (dstPort === 80 || dstPort === 8080 || dstPort === 8000) connection = "HTTP";
        else if (dstPort === 443) connection = "HTTPS";
        else connection = "TCP";
      } else if (/\bicmpl?\b/i.test(line)) {
        connection = "ICMP";
      } else if (/\bigmp\b/i.test(line)) {
        connection = "IGMP";
      } else if (/\bARP\b/i.test(line)) {
        connection = "ARP";
      } else {
        const pm = line.match(/\b(TCP|UDP|ICMP|IGMP)\b/i);
        if (pm) connection = pm[1].toUpperCase();
      }
      let m;
      while ((m = ipRegex.exec(line)) !== null) {
        const ip = m[1];
        if (!seen.has(ip)) {
          seen.add(ip);
          enrich(ip, connection, dstPort).catch((e) => console.error(e));
        }
      }
      ipRegex.lastIndex = 0;
    }
  }
})();

(async () => {
  const reader = proc.stderr.getReader();
  const decoder = new TextDecoder();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    process.stderr.write(decoder.decode(value));
  }
})();

Bun.serve({
  port: 1234,
  routes: {
    "/": new Response(html, {
      headers: { "Content-Type": "text/html" },
    }),
    "/events": (req) => {
      let controllerRef;
      const stream = new ReadableStream({
        start(controller) {
          controllerRef = controller;
          clients.add(controller);
          // Replay already-enriched IPs to late subscribers.
          for (const payload of cache.values()) send(controller, payload);
        },
        cancel() {
          if (controllerRef) clients.delete(controllerRef);
        },
      });
      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        },
      });
    },
  },
});


Bun.spawn(["open", "http://localhost:1234"])