export const FILE_UPLOAD_ERROR_MESSAGE: string;

export function isAllowedDependencyFileName(fileName: string): boolean;

export function validateDependencyFile(file: File | null | undefined): {
  valid: boolean;
  error: string;
};

export function acceptedDependencyFileTypes(): string;
