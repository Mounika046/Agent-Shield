import test from 'node:test';
import assert from 'node:assert/strict';

import {
  FILE_UPLOAD_ERROR_MESSAGE,
  isAllowedDependencyFileName,
  validateDependencyFile,
} from '../src/components/v3/fileUploadValidation.js';

test('rejects pdf upload', () => {
  const result = validateDependencyFile({ name: 'report.pdf' });
  assert.equal(result.valid, false);
  assert.equal(result.error, FILE_UPLOAD_ERROR_MESSAGE);
});

test('rejects docx upload', () => {
  const result = validateDependencyFile({ name: 'dependency-review.docx' });
  assert.equal(result.valid, false);
  assert.equal(result.error, FILE_UPLOAD_ERROR_MESSAGE);
});

test('accepts requirements.txt upload', () => {
  assert.equal(isAllowedDependencyFileName('requirements.txt'), true);
});

test('accepts package.json upload', () => {
  assert.equal(isAllowedDependencyFileName('package.json'), true);
});
