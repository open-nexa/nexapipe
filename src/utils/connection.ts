export type ConnectionType = 'ticket' | 'endpoint_id';

export interface ConnectionInfo {
  type: ConnectionType;
  value: string;
}

export function detectConnectionType(input: string): ConnectionInfo {
  const trimmed = input.trim();
  
  if (!trimmed) {
    return { type: 'ticket', value: '' };
  }
  
  if (trimmed.startsWith('nexapipe://') || trimmed.startsWith('ticket:')) {
    return { type: 'ticket', value: trimmed };
  }
  
  if (trimmed.startsWith('iroh://')) {
    const parts = trimmed.split('/');
    const idPart = parts[3];
    if (idPart) {
      return { type: 'endpoint_id', value: idPart };
    }
    return { type: 'endpoint_id', value: trimmed };
  }
  
  if (trimmed.length === 52 || trimmed.length === 64) {
    const isValidBase32 = /^[A-Z2-7]+$/.test(trimmed);
    const isValidHex = /^[0-9a-fA-F]+$/.test(trimmed);
    
    if (trimmed.length === 52 && isValidBase32) {
      return { type: 'endpoint_id', value: trimmed };
    }
    
    if (trimmed.length === 64 && isValidHex) {
      return { type: 'endpoint_id', value: trimmed };
    }
  }
  
  if (trimmed.length > 64 && trimmed.includes('_')) {
    return { type: 'ticket', value: trimmed };
  }
  
  if (trimmed.length > 100) {
    return { type: 'ticket', value: trimmed };
  }
  
  return { type: 'endpoint_id', value: trimmed };
}
