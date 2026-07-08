const ALLOWED_FILE_EXTENSIONS = ['.txt', '.json', '.toml', '.lock', '.yaml', '.yml'];

const ALLOWED_FILE_NAMES = new Set([
  'requirements.txt',
  'pyproject.toml',
  'package.json',
  'package-lock.json',
  'poetry.lock',
  'pipfile.lock',
]);

export const FILE_UPLOAD_ERROR_MESSAGE =
  'Unsupported file type. Please upload a dependency file such as requirements.txt, package.json, pyproject.toml, etc.';

export function isAllowedDependencyFileName(fileName) {
  const normalized = String(fileName || '').trim().toLowerCase();
  if (!normalized) return false;
  if (ALLOWED_FILE_NAMES.has(normalized)) return true;
  return ALLOWED_FILE_EXTENSIONS.some((extension) => normalized.endsWith(extension));
}

export function validateDependencyFile(file) {
  if (!file || !isAllowedDependencyFileName(file.name)) {
    return {
      valid: false,
      error: FILE_UPLOAD_ERROR_MESSAGE,
    };
  }
  return {
    valid: true,
    error: '',
  };
}

export function acceptedDependencyFileTypes() {
  return [...ALLOWED_FILE_EXTENSIONS, ...ALLOWED_FILE_NAMES].join(',');
}

