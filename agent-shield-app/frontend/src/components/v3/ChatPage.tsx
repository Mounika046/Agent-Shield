import { useEffect, useMemo, useReducer, useState } from 'react';
import { DataManagementPage } from '@idp/nitro-redwood';
import { checkChatBackendHealth, sendChatMessage, type ChatMode } from '../../api/chat.js';
import { ChatContainer } from './ChatContainer.js';
import { Composer } from './Composer.js';
import type { AttachedFile, ChatMessage } from './chatTypes.js';
import styles from './ChatPage.module.css';

type ChatState = {
  messages: ChatMessage[];
};

type ChatAction =
  | { type: 'append'; message: ChatMessage }
  | { type: 'replace'; id: string; message: ChatMessage }
  | { type: 'finishTyping'; id: string };

function chatReducer(state: ChatState, action: ChatAction): ChatState {
  if (action.type === 'append') {
    return { messages: [...state.messages, action.message] };
  }
  if (action.type === 'replace') {
    return {
      messages: state.messages.map((message) => (message.id === action.id ? action.message : message)),
    };
  }
  if (action.type === 'finishTyping') {
    return {
      messages: state.messages.map((message) =>
        message.id === action.id ? { ...message, status: 'done', displayedText: message.text } : message,
      ),
    };
  }
  return state;
}

function createId(prefix: string) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function createConversationId() {
  return `conv-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M12 3 5 6v6c0 4.8 2.9 7.9 7 9 4.1-1.1 7-4.2 7-9V6l-7-3Z"
        fill="none"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function UserIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M12 12a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm6 7a6 6 0 0 0-12 0"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

export function ChatPage() {
  const [state, dispatch] = useReducer(chatReducer, { messages: [] });
  const [mode, setMode] = useState<ChatMode>('fast');
  const [busy, setBusy] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const conversationId = useMemo(createConversationId, []);
  const hasStarted = state.messages.length > 0;

  useEffect(() => {
    checkChatBackendHealth()
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false));
  }, []);

  async function submitMessage(message: string, file?: AttachedFile) {
    if (busy) return;
    const activeMode = mode;
    const assistantMessageId = createId('assistant');
    dispatch({
      type: 'append',
      message: {
        id: createId('user'),
        role: 'user',
        text: message,
        status: 'done',
        mode: activeMode,
        fileName: file?.name,
      },
    });
    dispatch({
      type: 'append',
      message: {
        id: assistantMessageId,
        role: 'assistant',
        text: 'Performing analysis... response will be returned shortly.',
        status: 'pending',
        mode: activeMode,
      },
    });
    setBusy(true);

    try {
      const response = await sendChatMessage({
        message,
        mode: activeMode,
        conversation_id: conversationId,
        file_name: file?.name,
        file_content: file?.content,
      });
      dispatch({
        type: 'replace',
        id: assistantMessageId,
        message: {
          id: assistantMessageId,
          role: 'assistant',
          text: response.llm_response || response.message || 'I completed the analysis, but no written summary was returned.',
          status: 'typing',
          cards: response.cards,
          dependenciesDiscoveredTable: response.dependencies_discovered_table,
          vulnerableDependenciesTable: response.vulnerable_dependencies_table,
          licenseComplianceTable: response.license_compliance_table,
          dependencyGraphs: response.dependency_graphs,
          tableData: response.table_data,
          tableColumns: response.table_columns,
          mode: response.mode || activeMode,
          responseType: response.response_type,
        },
      });
      setBackendOnline(true);
    } catch (error) {
      dispatch({
        type: 'replace',
        id: assistantMessageId,
        message: {
          id: assistantMessageId,
          role: 'assistant',
          text: error instanceof Error ? error.message : 'Something went wrong. Please try again.',
          status: 'error',
          mode: activeMode,
          error: true,
        },
      });
      setBackendOnline(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <DataManagementPage
      pageTitle="Agent Shield"
      avatar={{ initials: 'AS' }}
      badge={{
        text: backendOnline === true ? 'Backend connected' : backendOnline === false ? 'Backend offline' : 'Checking backend',
        status: backendOnline === true ? 'success' : backendOnline === false ? 'danger' : 'neutral',
      }}
      primaryAction={{ label: 'Back to manual scan', display: 'on' }}
      onPrimaryAction={() => { window.location.hash = '#/'; }}
      displayMode="mixed"
      displayOptions={{ timestamp: false, density: 'compact' }}
      className={styles.page}
    >
      <div className={styles.workspace}>
        <div className={styles.chatLayout}>
          <ChatContainer
            messages={state.messages}
            busy={busy}
            backendOnline={backendOnline}
            emptyState={(
              <div className={styles.emptyState}>
                <span className={styles.introMark}><ShieldIcon /></span>
                <h1>How can AgentShield help?</h1>
                <p>Analyze a repository, dependency file, package vulnerability, or open-source license risk.</p>
              </div>
            )}
            onTypingDone={(id) => dispatch({ type: 'finishTyping', id })}
          />
          <div className={styles.composerDock}>
            <Composer
              mode={mode}
              busy={busy}
              autoFocus={!hasStarted}
              compact={hasStarted}
              placeholder={hasStarted ? 'Ask a follow-up...' : 'Ask AgentShield to analyze repositories, dependencies, vulnerabilities, or licenses...'}
              onModeChange={setMode}
              onSubmit={submitMessage}
            />
          </div>
        </div>
      </div>
    </DataManagementPage>
  );
}
