import type { AgentChatRequest, AgentChatResponse, HealthResponse, ScanMode } from './agentShieldApi.js';

export type ChatMode = ScanMode;
export type ChatRequestPayload = AgentChatRequest;
export type ChatResponsePayload = AgentChatResponse;

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;
const CHAT_API_BASE_URL = (configuredBaseUrl || '/api').replace(/\/$/, '');

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${CHAT_API_BASE_URL}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...init?.headers,
      },
    });
  } catch {
    throw new Error('Cannot reach the AgentShield backend. Start it on port 8070 and try again.');
  }

  const payload = (await response.json().catch(() => null)) as { detail?: string; message?: string } | null;
  if (!response.ok) {
    throw new Error(payload?.detail || payload?.message || `Backend request failed with status ${response.status}.`);
  }
  return payload as T;
}

export function checkChatBackendHealth(): Promise<HealthResponse> {
  return requestJson<HealthResponse>('/health');
}

export function sendChatMessage(payload: ChatRequestPayload): Promise<ChatResponsePayload> {
  return requestJson<ChatResponsePayload>('/agent/chat', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}
