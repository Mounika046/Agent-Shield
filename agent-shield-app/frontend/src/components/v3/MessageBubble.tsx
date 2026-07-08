import { useCallback, useState } from 'react';
import { Button } from '@idp/nitro-redwood';
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
  const isSystem = message.role === 'system';
  const [copied, setCopied] = useState(false);
  const finishTyping = useCallback(() => onTypingDone(message.id), [message.id, onTypingDone]);

  async function copyResponse() {
    await navigator.clipboard.writeText(message.text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className={`${styles.messageRow} ${isUser ? styles.messageRowUser : ''} ${isSystem ? styles.messageRowSystem : ''}`}>
      <article className={`${styles.messageBubble} ${isUser ? styles.userBubble : isSystem ? styles.systemBubble : styles.assistantBubble}`}>
        <div className={styles.messageMeta}>
          <span>{isUser ? 'You' : isSystem ? 'Status' : 'Agent Shield'}</span>
          {message.mode && <span>{message.mode}</span>}
        </div>
        <div className={`${styles.messageText} ${message.error ? styles.errorText : ''}`}>
          {message.status === 'typing' && !isUser ? (
            <TypingRenderer text={message.text} active onDone={finishTyping} />
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
        {!isUser && !isSystem && message.status === 'done' && (
          <div className={styles.assistantActions}>
            <Button
              label={copied ? 'Copied' : 'Copy response'}
              chroming="borderless"
              tooltip="Copy assistant response"
              onClick={copyResponse}
            />
          </div>
        )}
      </article>
    </div>
  );
}
