import type { ChatMessage } from './chatTypes.js';
import { MessageBubble } from './MessageBubble.js';
import styles from './ChatPage.module.css';

type MessageListProps = {
  messages: ChatMessage[];
  busy?: boolean;
  onTypingDone: (id: string) => void;
};

export function MessageList({ messages, busy, onTypingDone }: MessageListProps) {
  return (
    <div className={styles.messageList}>
      {messages.map((message) => (
        <MessageBubble key={message.id} message={message} onTypingDone={onTypingDone} />
      ))}
    </div>
  );
}

