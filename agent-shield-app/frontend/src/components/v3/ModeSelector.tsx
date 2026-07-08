import type { ScanMode } from '../../api/agentShieldApi.js';
import { Select } from '@idp/nitro-redwood';
import styles from './ChatPage.module.css';

type ModeSelectorProps = {
  value: ScanMode;
  disabled?: boolean;
  onChange: (mode: ScanMode) => void;
};

export function ModeSelector({ value, disabled, onChange }: ModeSelectorProps) {
  const options = [
    {
      value: 'fast' as const,
      label: 'Fast',
      description: 'Checks exact dependency versions for known vulnerabilities.',
    },
    {
      value: 'detailed' as const,
      label: 'Detailed',
      description: 'Adds license compliance and package metadata to vulnerability analysis.',
    },
    {
      value: 'developer' as const,
      label: 'Developer',
      description: 'Adds deeper technical context intended for developer investigation.',
    },
  ];
  const selectedDescription = options.find((option) => option.value === value)?.description;

  return (
    <div className={styles.modeSelectWrap} title={selectedDescription}>
      <Select
        label="Analysis mode"
        labelEdge="none"
        data={options}
        value={value}
        disabled={disabled}
        itemText="label"
        itemRenderer={(item) => <span title={String(item.description || '')}>{item.label}</span>}
        userAssistanceDensity="compact"
        onChange={(nextValue) => onChange(nextValue as ScanMode)}
        width="120px"
        className={styles.modeSelect}
      />
    </div>
  );
}
