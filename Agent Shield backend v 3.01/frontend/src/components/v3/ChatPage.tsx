import { useEffect, useMemo, useReducer, useState } from 'react';
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

const quickActions = [
  'Check vulnerabilities',
  'License compliance',
  'Dependency analysis',
  'Risk assessment',
] as const;

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
    <main className={styles.page}>
      <header className={styles.topBar}>
        <div className={styles.brandBlock}>
          <div className={styles.brand}>
            <span className={styles.mark}>
              <ShieldIcon />
            </span>
            <span className={styles.brandText}>
              <strong>Agent Shield</strong>
            </span>
          </div>
          <span
            className={`${styles.statusBadge} ${
              backendOnline === false
                ? styles.statusBadgeOffline
                : backendOnline === true
                  ? styles.statusBadgeOnline
                  : styles.statusBadgeChecking
            }`}
          >
            {backendOnline === false ? 'Backend offline' : backendOnline === true ? 'Backend connected' : 'Checking backend'}
          </span>
        </div>

        <button type="button" className={styles.profileButton} aria-label="User profile">
          <UserIcon />
        </button>
      </header>

      {!hasStarted ? (
        <section className={styles.landing}>
          <div className={styles.landingInner}>
            <h1 className={styles.heading}>Hello, I&apos;m AgentShield</h1>
            <p className={styles.subheading}>How can I help you with your security analysis today?</p>
            <Composer
              mode={mode}
              busy={busy}
              autoFocus
              placeholder="Ask me anything about your dependencies, vulnerabilities, or license risks..."
              onModeChange={setMode}
              onSubmit={submitMessage}
            />
            <div className={styles.quickActions} aria-label="Suggested actions">
              {quickActions.map((action, index) => (
                <button key={action} type="button" className={styles.quickAction} onClick={() => submitMessage(action)}>
                  <span className={styles.quickActionIcon} aria-hidden="true">
                    {index === 0 ? 'S' : index === 1 ? 'L' : index === 2 ? 'D' : 'R'}
                  </span>
                  <span>{action}</span>
                </button>
              ))}
            </div>
          </div>
        </section>
      ) : (
        <>
          <ChatContainer
            messages={state.messages}
            busy={busy}
            backendOnline={backendOnline}
            onTypingDone={(id) => dispatch({ type: 'finishTyping', id })}
          />
          <div className={styles.composerDock}>
            <Composer
              mode={mode}
              busy={busy}
              compact
              placeholder="Ask a follow-up about dependencies, vulnerabilities, or remediation..."
              onModeChange={setMode}
              onSubmit={submitMessage}
            />
          </div>
        </>
      )}
    </main>
  );
}
