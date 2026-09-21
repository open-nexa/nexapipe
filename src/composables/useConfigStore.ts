import { ref, watch, reactive } from "vue";
import type {
  ProxyConfig,
  ProxyStatus,
  NodeConfig,
  LoadBalancingStrategy,
  EndpointLink,
  LinkKind,
} from "../types";
import { detectConnectionType } from "../utils/connection";

const STORAGE_KEY = "nexa-config";

function generateNodeId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

const defaultConfig: ProxyConfig = {
  nodes: [],
  domains: [],
  localAddr: "127.0.0.1:8080",
  dnsAddr: "10.0.0.254:53",
  upstreamDns: "223.5.5.5:53",
  loadBalancing: "round_robin",
  tunName: "nexa-tun",
  // The explicit forwarding-mode flag; this store is replaced by `stores/config.ts` in Phase 3.
  useTun: false,
  useService: false,
  relayMode: 'pinned' as const,
  relayUrl: '',
  forceRelay: false,
  twoFactorEnabled: false,
  twoFactorClientId: '',
  twoFactorSecret: '',
  twoFactorAlgorithm: 'sha1' as const,
};

function migrateOldConfig(old: any): ProxyConfig {
  const config = { ...defaultConfig };
  const oldDomains = old.domains || [];

  if (old.connectionType || old.ticket || old.endpointId) {
    const node: NodeConfig = {
      id: generateNodeId(),
      connectionType: old.connectionType || 'ticket',
      ticket: old.ticket || "",
      endpointId: old.endpointId || "",
      domains: oldDomains,
    };
    config.nodes = [node];
  }

  if (old.domains) {
    config.domains = oldDomains;
  }
  if (old.localAddr) {
    config.localAddr = old.localAddr;
  }
  if (old.dnsAddr) {
    config.dnsAddr = old.dnsAddr;
  }
  if (old.upstreamDns) {
    config.upstreamDns = old.upstreamDns;
  }
  if (old.useService !== undefined) {
    config.useService = old.useService;
  }
  if (old.tunName) {
    config.tunName = old.tunName;
  }
  if (old.loadBalancing) {
    config.loadBalancing = old.loadBalancing;
  }
  if (old.relayMode) { config.relayMode = old.relayMode; }
  if (old.relayUrl !== undefined) { config.relayUrl = old.relayUrl; }
  if (old.forceRelay !== undefined) { config.forceRelay = old.forceRelay; }
  if (old.twoFactorEnabled !== undefined) { config.twoFactorEnabled = old.twoFactorEnabled; }
  if (old.twoFactorClientId !== undefined) { config.twoFactorClientId = old.twoFactorClientId; }
  if (old.twoFactorSecret !== undefined) { config.twoFactorSecret = old.twoFactorSecret; }
  if (old.twoFactorAlgorithm !== undefined) { config.twoFactorAlgorithm = old.twoFactorAlgorithm; }

  return config;
}

function loadConfig(): ProxyConfig {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      if (parsed.nodes && Array.isArray(parsed.nodes)) {
        parsed.nodes = parsed.nodes.map((node: any) => ({
          ...node,
          domains: node.domains || [],
        }));
        return { ...defaultConfig, ...parsed };
      }
      return migrateOldConfig(parsed);
    }
  } catch (e) {
    console.error("Failed to load config from localStorage:", e);
  }
  return { ...defaultConfig };
}

function saveConfig(config: ProxyConfig) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  } catch (e) {
    console.error("Failed to save config to localStorage:", e);
  }
}

const config = reactive<ProxyConfig>(loadConfig());

const proxyStatus = ref<ProxyStatus>({ running: false, mode: "stopped" });

/**
 * How each node is currently reaching its backend, filled in from the Rust side while the proxy
 * is up. Empty whenever nothing is running, which is what keeps a stale icon off the screen.
 */
const endpointLinks = ref<EndpointLink[]>([]);

watch(
  () => ({ ...config }),
  (newConfig) => {
    saveConfig(newConfig);
  },
  { deep: true }
);

export function useConfigStore() {
  function updateConfig(newConfig: Partial<ProxyConfig>) {
    Object.assign(config, newConfig);
  }

  function addNode(node?: Partial<NodeConfig>) {
    const newNode: NodeConfig = {
      id: node?.id || generateNodeId(),
      connectionType: node?.connectionType || 'ticket',
      ticket: node?.ticket || "",
      endpointId: node?.endpointId || "",
      domains: node?.domains || [],
    };
    config.nodes.push(newNode);
  }

  function removeNode(nodeId: string) {
    const index = config.nodes.findIndex(n => n.id === nodeId);
    if (index !== -1) {
      config.nodes.splice(index, 1);
    }
  }

  function updateNode(nodeId: string, updates: Partial<NodeConfig>) {
    const node = config.nodes.find(n => n.id === nodeId);
    if (node) {
      Object.assign(node, updates);
    }
  }

  function updateConnectionString(nodeId: string, value: string) {
    const node = config.nodes.find(n => n.id === nodeId);
    if (node) {
      const info = detectConnectionType(value);
      node.connectionType = info.type;
      if (info.type === 'ticket') {
        node.ticket = info.value;
        node.endpointId = "";
      } else {
        node.endpointId = info.value;
        node.ticket = "";
      }
    }
  }

  function updateNodeDomains(nodeId: string, domains: string[]) {
    const node = config.nodes.find(n => n.id === nodeId);
    if (node) {
      node.domains = domains;
    }
  }

  function setLoadBalancing(strategy: LoadBalancingStrategy) {
    config.loadBalancing = strategy;
  }

  function setProxyStatus(status: ProxyStatus) {
    proxyStatus.value = status;
  }

  function setEndpointLinks(links: EndpointLink[]) {
    endpointLinks.value = links;
  }

  /**
   * The runtime link kind of a node, or null when nothing is connected to it — the normal
   * answer before the proxy is started.
   */
  function linkKindFor(node: NodeConfig): LinkKind | null {
    const connection = node.connectionType === "ticket" ? node.ticket : node.endpointId;
    if (!connection) return null;
    return endpointLinks.value.find((link) => link.connection === connection)?.link ?? null;
  }

  function resetConfig() {
    Object.assign(config, defaultConfig);
  }

  return {
    config,
    proxyStatus,
    endpointLinks,
    updateConfig,
    addNode,
    removeNode,
    updateNode,
    updateConnectionString,
    updateNodeDomains,
    setLoadBalancing,
    setProxyStatus,
    setEndpointLinks,
    linkKindFor,
    resetConfig,
  };
}
