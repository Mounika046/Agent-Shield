import { type ReactNode, useEffect, useRef } from 'react';
import type { ChatMessage } from './chatTypes.js';
import { MessageList } from './MessageList.js';
import styles from './ChatPage.module.css';

type ChatContainerProps = {
  messages: ChatMessage[];
  busy?: boolean;
  backendOnline: boolean | null;
  emptyState?: ReactNode;
  onTypingDone: (id: string) => void;
};

export function ChatContainer({ messages, busy, backendOnline, emptyState, onTypingDone }: ChatContainerProps) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const shouldAutoScrollRef = useRef(true);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (viewport && shouldAutoScrollRef.current) {
      viewport.scrollTo({ top: viewport.scrollHeight, behavior: 'smooth' });
    }
  }, [messages, busy]);

  return (
    <section className={styles.chatShell} data-backend={backendOnline === true ? 'online' : backendOnline === false ? 'offline' : 'checking'}>
      <div
        ref={viewportRef}
        className={styles.messageViewport}
        onScroll={(event) => {
          const element = event.currentTarget;
          shouldAutoScrollRef.current = element.scrollHeight - element.scrollTop - element.clientHeight < 120;
        }}
      >
        {messages.length ? <MessageList messages={messages} busy={busy} onTypingDone={onTypingDone} /> : emptyState}
      </div>
    </section>
  );
}
