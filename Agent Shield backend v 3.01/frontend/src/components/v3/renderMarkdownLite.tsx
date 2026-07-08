import type { ReactNode } from 'react';

type InlineToken =
  | { type: 'text'; value: string }
  | { type: 'bold'; value: string }
  | { type: 'italic'; value: string };

function parseInlineMarkdown(text: string): InlineToken[] {
  const tokens: InlineToken[] = [];
  const pattern = /(\*\*[^*]+\*\*|\*[^*]+\*)/g;
  let cursor = 0;

  for (const match of text.matchAll(pattern)) {
    const index = match.index ?? 0;
    if (index > cursor) {
      tokens.push({ type: 'text', value: text.slice(cursor, index) });
    }
    const value = match[0] || '';
    if (value.startsWith('**') && value.endsWith('**')) {
      tokens.push({ type: 'bold', value: value.slice(2, -2) });
    } else if (value.startsWith('*') && value.endsWith('*')) {
      tokens.push({ type: 'italic', value: value.slice(1, -1) });
    } else {
      tokens.push({ type: 'text', value });
    }
    cursor = index + value.length;
  }

  if (cursor < text.length) {
    tokens.push({ type: 'text', value: text.slice(cursor) });
  }

  return tokens;
}

function renderInlineMarkdown(text: string): ReactNode[] {
  return parseInlineMarkdown(text).map((token, index) => {
    if (token.type === 'bold') {
      return <strong key={index}>{token.value}</strong>;
    }
    if (token.type === 'italic') {
      return <em key={index}>{token.value}</em>;
    }
    return <span key={index}>{token.value}</span>;
  });
}

export function renderMarkdownLite(text: string): ReactNode[] {
  return text.split('\n').map((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) {
      return <p key={index}>&nbsp;</p>;
    }
    return <p key={index}>{renderInlineMarkdown(trimmed)}</p>;
  });
}
