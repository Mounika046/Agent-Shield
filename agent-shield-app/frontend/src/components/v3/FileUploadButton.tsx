import { useRef } from 'react';
import { Button } from '@idp/nitro-redwood';
import type { AttachedFile } from './chatTypes.js';
import {
  acceptedDependencyFileTypes,
  validateDependencyFile,
} from './fileUploadValidation.js';
import styles from './ChatPage.module.css';

type FileUploadButtonProps = {
  disabled?: boolean;
  onFileError: (message: string) => void;
  onFileSelected: (file: AttachedFile) => void;
};
 
export function FileUploadButton({ disabled, onFileError, onFileSelected }: FileUploadButtonProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  async function handleChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const validation = validateDependencyFile(file);
    if (!validation.valid) {
      onFileError(validation.error);
      event.target.value = '';
      return;
    }
    onFileSelected({ name: file.name, content: await file.text() });
    event.target.value = '';
  }

  return (
    <>
      <Button
        label="Attach dependency file"
        aria-label="Attach dependency file"
        chroming="borderless"
        display="icons"
        startIcon={(
          <svg className={styles.attachIcon} viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="m8.5 12.5 5.8-5.8a3 3 0 0 1 4.2 4.2l-7.2 7.2a5 5 0 0 1-7.1-7.1l7.3-7.3"
              fill="none"
              stroke="currentColor"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="1.8"
            />
          </svg>
        )}
        className={styles.attachmentIconButton}
        disabled={disabled}
        onClick={() => inputRef.current?.click()}
      />
      <input ref={inputRef} type="file" accept={acceptedDependencyFileTypes()} hidden onChange={handleChange} />
    </>
  );
}
