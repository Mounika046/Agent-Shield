import { useEffect, useRef } from 'react';
import type { ChatMessage } from './chatTypes.js';
import { MessageList } from './MessageList.js';
import styles from './ChatPage.module.css';

type ChatContainerProps = {
  messages: ChatMessage[];
  busy?: boolean;
  backendOnline: boolean | null;
  onTypingDone: (id: string) => void;
};

export function ChatContainer({ messages, busy, backendOnline, onTypingDone }: ChatContainerProps) {
  const viewportRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    viewportRef.current?.scrollTo({ top: viewportRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, busy]);

  return (
    <section className={styles.chatShell} data-backend={backendOnline === true ? 'online' : backendOnline === false ? 'offline' : 'checking'}>
      <div ref={viewportRef} className={styles.messageViewport}>
        <MessageList messages={messages} busy={busy} onTypingDone={onTypingDone} />
      </div>
    </section>
  );
}
