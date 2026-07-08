import { useCallback } from 'react';
import { ResponseArtifacts } from './ResponseArtifacts.js';
import type { ChatMessage } from './chatTypes.js';
import { renderMarkdownLite } from './renderMarkdownLite.js';
import { TableRenderer } from './TableRenderer.js';
import { TypingRenderer } from './TypingRenderer.js';
import styles from './ChatPage.module.css';

type MessageBubbleProps = {
  message: ChatMessage;
  onTypingDone: (id: string) => void;
};

export function MessageBubble({ message, onTypingDone }: MessageBubbleProps) {
  const isUser = message.role === 'user';
  const finishTyping = useCallback(() => onTypingDone(message.id), [message.id, onTypingDone]);

  return (
    <div className={`${styles.messageRow} ${isUser ? styles.messageRowUser : ''}`}>
      <article className={`${styles.messageBubble} ${isUser ? styles.userBubble : styles.assistantBubble}`}>
        <div className={styles.messageMeta}>
          <span>{isUser ? 'You' : 'Agent Shield'}</span>
          {message.mode && <span>{message.mode}</span>}
        </div>
        <div className={`${styles.messageText} ${message.error ? styles.errorText : ''}`}>
          {message.status === 'typing' && !isUser ? (
            <p>
              <TypingRenderer text={message.text} active onDone={finishTyping} />
            </p>
          ) : (
            renderMarkdownLite(message.displayedText || message.text)
          )}
        </div>
        {message.fileName && <span className={styles.fileChip}>{message.fileName}</span>}
        {!isUser && message.status === 'done' && (
          <>
            <ResponseArtifacts
              cards={message.cards}
              dependenciesDiscoveredTable={message.dependenciesDiscoveredTable}
              vulnerableDependenciesTable={message.vulnerableDependenciesTable}
              licenseComplianceTable={message.licenseComplianceTable}
              dependencyGraphs={message.dependencyGraphs}
            />
            <TableRenderer data={message.tableData} columns={message.tableColumns} />
          </>
        )}
      </article>
    </div>
  );
}
