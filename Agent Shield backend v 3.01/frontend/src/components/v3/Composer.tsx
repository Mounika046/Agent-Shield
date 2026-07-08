import { useState } from 'react';
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

function SettingsIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M4 7h7m3 0h6M7 7a2 2 0 1 0 0 .01M4 17h3m3 0h10M13 17a2 2 0 1 0 0 .01"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function SendIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M21 3 10 14"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
      <path
        d="m21 3-7 18-4-7-7-4 18-7Z"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

export function Composer({
  mode,
  busy,
  autoFocus,
  placeholder = 'Ask Agent Shield',
  compact,
  onModeChange,
  onSubmit,
}: ComposerProps) {
  const [message, setMessage] = useState('');
  const [file, setFile] = useState<AttachedFile | undefined>();
  const [fileError, setFileError] = useState('');
  const canSubmit = Boolean(message.trim() || file) && !busy;

  function submit() {
    if (!canSubmit) return;
    onSubmit(message.trim() || `Analyze ${file?.name}`, file);
    setMessage('');
    setFile(undefined);
    setFileError('');
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      submit();
    }
  }

  return (
    <form
      className={`${styles.composer} ${compact ? styles.composerCompact : ''}`}
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <div className={styles.inputWrap}>
        <input
          className={styles.input}
          value={message}
          autoFocus={autoFocus}
          disabled={busy}
          placeholder={placeholder}
          onChange={(event) => setMessage(event.target.value)}
          onKeyDown={handleKeyDown}
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

      <div className={styles.composerFooter}>
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
          <button
            type="button"
            className={styles.iconButton}
            aria-label="Composer settings"
            title="Composer settings"
            disabled={busy}
          >
            <SettingsIcon />
          </button>
        </div>

        <div className={styles.composerActions}>
          <ModeSelector value={mode} disabled={busy} onChange={onModeChange} />
          <button type="submit" className={styles.sendButton} aria-label="Send message" disabled={!canSubmit}>
            <SendIcon />
          </button>
        </div>
      </div>
    </form>
  );
}
