import { useEffect, useMemo, useState } from 'react';
import styles from './ChatPage.module.css';

type TypingRendererProps = {
  text: string;
  active: boolean;
  onDone: () => void;
};

export function TypingRenderer({ text, active, onDone }: TypingRendererProps) {
  const words = useMemo(() => text.split(/(\s+)/), [text]);
  const [visibleCount, setVisibleCount] = useState(active ? 0 : words.length);

  useEffect(() => {
    if (!active) {
      setVisibleCount(words.length);
      return;
    }
    setVisibleCount(0);
    if (!words.length) {
      onDone();
      return;
    }
    const interval = window.setInterval(() => {
      setVisibleCount((current) => {
        const next = Math.min(current + 2, words.length);
        if (next >= words.length) {
          window.clearInterval(interval);
          window.setTimeout(onDone, 120);
        }
        return next;
      });
    }, 42);
    return () => window.clearInterval(interval);
  }, [active, onDone, words.length]);

  return (
    <>
      {words.slice(0, visibleCount).join('')}
      {active && visibleCount < words.length && <span className={styles.typingCursor} aria-hidden="true" />}
    </>
  );
}
