import type { ScanMode } from '../../api/agentShieldApi.js';
import styles from './ChatPage.module.css';

type ModeSelectorProps = {
  value: ScanMode;
  disabled?: boolean;
  onChange: (mode: ScanMode) => void;
};

export function ModeSelector({ value, disabled, onChange }: ModeSelectorProps) {
  return (
    <select
      className={styles.modeSelect}
      aria-label="Analysis mode"
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value as ScanMode)}
    >
      <option value="fast">Fast</option>
      <option value="detailed">Detailed</option>
      <option value="developer">Developer</option>
    </select>
  );
}
