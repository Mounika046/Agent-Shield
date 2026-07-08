import { useRef } from 'react';
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
      <button
        type="button"
        className={styles.fileButton}
        aria-label="Attach dependency or config file"
        title="Attach file"
        disabled={disabled}
        onClick={() => inputRef.current?.click()}
      >
        +
      </button>
      <input ref={inputRef} type="file" accept={acceptedDependencyFileTypes()} hidden onChange={handleChange} />
    </>
  );
}
