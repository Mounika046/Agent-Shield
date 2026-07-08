import type { ReactNode } from 'react';
import styles from './ChatPage.module.css';

const SECTION_HEADINGS = new Set([
  'summary',
  'package checked',
  'security findings',
  'top vulnerabilities',
  'vulnerabilities',
  'recommended upgrade',
  'remediation guidance',
  'license analysis',
  'license compliance',
  'developer guidance',
  'dependency quality',
  'upgrade priority',
  'engineering guidance',
  'confidence',
  'limitations',
  'confidence / limitations',
  'useful links',
  'next steps',
]);

function cleanHeading(text: string): string {
  return text
    .trim()
    .replace(/^\d+[.)]\s*/, '')
    .replace(/^#{1,4}\s*/, '')
    .replace(/^\*\*(.+)\*\*$/, '$1')
    .replace(/:$/, '')
    .trim();
}

function isSectionHeading(text: string): boolean {
  return SECTION_HEADINGS.has(cleanHeading(text).toLowerCase());
}

function isFindingHeading(text: string): boolean {
  const cleaned = cleanHeading(text);
  return /^(CVE-|GHSA-|PYSEC-|OSV-)/i.test(cleaned) ||
    (/^\d+[.)]\s*/.test(text) && /(?:CVE-|GHSA-|critical|high|moderate|medium|low)/i.test(text));
}

function renderInline(text: string): ReactNode[] {
  const pattern = /(\[[^\]]+\]\(https?:\/\/[^)]+\)|https?:\/\/[^\s)]+|`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g;
  const nodes: ReactNode[] = [];
  let cursor = 0;

  for (const match of text.matchAll(pattern)) {
    const index = match.index ?? 0;
    if (index > cursor) nodes.push(text.slice(cursor, index));
    const token = match[0];
    const markdownLink = token.match(/^\[([^\]]+)\]\((https?:\/\/[^)]+)\)$/);
    if (markdownLink) {
      nodes.push(<a key={index} href={markdownLink[2]} target="_blank" rel="noreferrer">{markdownLink[1]}</a>);
    } else if (/^https?:\/\//.test(token)) {
      nodes.push(<a key={index} href={token} target="_blank" rel="noreferrer">{token}</a>);
    } else if (token.startsWith('`')) {
      nodes.push(<code key={index}>{token.slice(1, -1)}</code>);
    } else if (token.startsWith('**')) {
      nodes.push(<strong key={index}>{token.slice(2, -2)}</strong>);
    } else {
      nodes.push(<em key={index}>{token.slice(1, -1)}</em>);
    }
    cursor = index + token.length;
  }

  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes;
}

function renderParagraph(text: string, key: number): ReactNode {
  const labeled = text.match(/^([A-Z][^:]{1,38}):\s+(.+)$/);
  if (labeled) {
    return <p key={key}><strong>{labeled[1]}:</strong> {renderInline(labeled[2])}</p>;
  }
  return <p key={key}>{renderInline(text)}</p>;
}

export function renderMarkdownLite(text: string): ReactNode[] {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const blocks: ReactNode[] = [];
  let index = 0;

  while (index < lines.length) {
    const trimmed = lines[index].trim();

    if (!trimmed) {
      index += 1;
      continue;
    }

    if (trimmed.startsWith('```')) {
      const language = trimmed.slice(3).trim();
      const code: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].trim().startsWith('```')) {
        code.push(lines[index]);
        index += 1;
      }
      blocks.push(
        <div key={`code-${index}`} className={styles.codeBlock}>
          {language && <span className={styles.codeLanguage}>{language}</span>}
          <pre><code>{code.join('\n')}</code></pre>
        </div>,
      );
      index += 1;
      continue;
    }

    if (/^#{1,3}\s+/.test(trimmed) || isSectionHeading(trimmed)) {
      const content = cleanHeading(trimmed);
      blocks.push(<h3 key={index} className={styles.responseHeading}>{renderInline(content)}</h3>);
      index += 1;
      continue;
    }

    if (isFindingHeading(trimmed)) {
      blocks.push(<h4 key={index} className={styles.responseSubheading}>{renderInline(cleanHeading(trimmed))}</h4>);
      index += 1;
      continue;
    }

    if (/^[-*•]\s+/.test(trimmed)) {
      const items: string[] = [];
      while (index < lines.length && /^[-*•]\s+/.test(lines[index].trim())) {
        items.push(lines[index].trim().replace(/^[-*•]\s+/, ''));
        index += 1;
      }
      blocks.push(<ul key={`ul-${index}`}>{items.map((item, itemIndex) => <li key={itemIndex}>{renderInline(item)}</li>)}</ul>);
      continue;
    }

    if (/^\d+[.)]\s+/.test(trimmed)) {
      const items: string[] = [];
      while (index < lines.length && /^\d+[.)]\s+/.test(lines[index].trim()) && !isFindingHeading(lines[index].trim())) {
        items.push(lines[index].trim().replace(/^\d+[.)]\s+/, ''));
        index += 1;
      }
      if (items.length) {
        blocks.push(<ol key={`ol-${index}`}>{items.map((item, itemIndex) => <li key={itemIndex}>{renderInline(item)}</li>)}</ol>);
        continue;
      }
    }

    blocks.push(renderParagraph(trimmed, index));
    index += 1;
  }

  return blocks;
}
