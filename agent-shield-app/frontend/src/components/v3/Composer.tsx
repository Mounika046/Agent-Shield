import { useLayoutEffect, useRef, useState } from 'react';
import { Button } from '@idp/nitro-redwood';
import type { ScanMode } from '../../api/agentShieldApi.js';
import type { AttachedFile } from './chatTypes.js';
import { FileUploadButton } from './FileUploadButton.js';
import { ModeSelector } from './ModeSelector.js';
import styles from './ChatPage.module.css';

type ComposerProps = {
  mode: ScanMode;
  busy?: boolean;
  autoFocus?: boolean;
  placeholder?: string;
  compact?: boolean;
  onModeChange: (mode: ScanMode) => void;
  onSubmit: (message: string, file?: AttachedFile) => void;
};

export function Composer({
  mode,
  busy,
  autoFocus,
  placeholder = 'Ask AgentShield to analyze repositories, dependencies, vulnerabilities, or licenses...',
  compact,
  onModeChange,
  onSubmit,
}: ComposerProps) {
  const [message, setMessage] = useState('');
  const [file, setFile] = useState<AttachedFile | undefined>();
  const [fileError, setFileError] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const canSubmit = Boolean(message.trim() || file) && !busy;

  useLayoutEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;

    textarea.style.height = 'auto';
    const computed = window.getComputedStyle(textarea);
    const lineHeight = Number.parseFloat(computed.lineHeight) || 24;
    const padding = Number.parseFloat(computed.paddingTop) + Number.parseFloat(computed.paddingBottom);
    const maxHeight = lineHeight * 8 + padding;
    const nextHeight = Math.min(textarea.scrollHeight, maxHeight);

    textarea.style.height = `${nextHeight}px`;
    textarea.style.overflowY = textarea.scrollHeight > maxHeight ? 'auto' : 'hidden';
  }, [message]);

  function submit() {
    if (!canSubmit) return;
    onSubmit(message.trim() || `Analyze ${file?.name}`, file);
    setMessage('');
    setFile(undefined);
    setFileError('');
  }

  return (
    <form
      className={`${styles.composer} ${compact ? styles.composerCompact : ''}`}
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
      onKeyDownCapture={(event) => {
        if (
          event.key === 'Enter' &&
          !event.shiftKey &&
          !event.nativeEvent.isComposing &&
          (event.target as HTMLElement).tagName === 'TEXTAREA'
        ) {
          event.preventDefault();
          submit();
        }
      }}
    >
      <div className={styles.inputWrap}>
        <textarea
          ref={textareaRef}
          aria-label="Message"
          className={styles.composerTextArea}
          value={message}
          disabled={busy}
          placeholder={placeholder}
          rows={1}
          autoFocus={autoFocus}
          onChange={(event) => setMessage(event.currentTarget.value)}
        />
        {fileError && <p className={styles.fileError}>{fileError}</p>}
        {file && (
          <span className={styles.attachment}>
            {file.name}
            <button
              type="button"
              className={styles.removeAttachment}
              aria-label="Remove attached file"
              onClick={() => setFile(undefined)}
            >
              x
            </button>
          </span>
        )}
      </div>

      <div className={styles.composerToolbar}>
        <div className={styles.composerTools}>
          <FileUploadButton
            disabled={busy}
            onFileError={(errorMessage) => {
              setFile(undefined);
              setFileError(errorMessage);
            }}
            onFileSelected={(selectedFile) => {
              setFileError('');
              setFile(selectedFile);
            }}
          />
        </div>

        <div className={styles.composerActions}>
          <ModeSelector value={mode} disabled={busy} onChange={onModeChange} />
          <Button
            label={busy ? 'Analyzing' : 'Send'}
            aria-label={busy ? 'AgentShield is analyzing' : 'Send message'}
            chroming="callToAction"
            display="icons"
            startIcon={busy ? <span className={styles.sendSpinner} aria-hidden="true" /> : (
              <svg className={styles.sendIcon} viewBox="0 0 24 24" aria-hidden="true">
                <path d="M12 19V5m0 0-6 6m6-6 6 6" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" />
              </svg>
            )}
            className={styles.sendButton}
            disabled={!canSubmit}
            onClick={submit}
          />
        </div>
      </div>
    </form>
  );
}
