import { useRef, useState } from 'react';
import { Button, Card, DataManagementPage, EmptyState } from '@idp/nitro-redwood';
import styles from './AgentShieldWorkspace.module.css';

export function AgentShieldWorkspace() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState('');

  return (
    <DataManagementPage
      pageTitle="Agent Shield"
      pageSubtitle="Check project dependencies for CVE exposure and open-source license risk."
      avatar={{ initials: 'AS' }}
      badge={{ text: 'Ready', status: 'neutral' }}
      displayMode="light"
      displayOptions={{ timestamp: false, density: 'compact' }}
      primaryAction={{ label: 'Analyze dependencies', disabled: true }}
      className={styles.page}
    >
      <div className={styles.workspace}>
        <Card
          overlineText="Requirements file"
          primaryText={fileName || 'Upload your project dependencies'}
          secondaryText={fileName ? 'File selected. Analysis will be enabled when the backend is connected.' : 'Select a Python requirements .txt file.'}
          badge={fileName ? { text: 'Selected', status: 'info', emphasis: 'subtle' } : undefined}
          responsiveWidth
          containerStyle={{ width: '100%' }}
        >
          <div className={styles.dropZone}>
            <input
              ref={fileInputRef}
              className={styles.fileInput}
              type="file"
              accept=".txt,text/plain"
              aria-label="Choose requirements file"
              onChange={(event) => setFileName(event.target.files?.[0]?.name ?? '')}
            />
            <div>
              <strong>{fileName ? 'Replace requirements file' : 'Choose requirements.txt'}</strong>
              <p>The file will be sent to the analysis backend after integration.</p>
            </div>
            <Button
              label={fileName ? 'Choose another file' : 'Choose file'}
              chroming="outlined"
              onClick={() => fileInputRef.current?.click()}
            />
          </div>
        </Card>

        <section className={styles.capabilityGrid} aria-label="Analysis results">
          <Card
            overlineText="Security results"
            primaryText="CVE detection"
            secondaryText="Known vulnerabilities, severity, affected versions, and remediation will appear here."
            responsiveWidth
            containerStyle={{ width: '100%' }}
          >
            <EmptyState
              primaryText="No CVE results yet"
              secondaryText="Results will appear after backend integration."
              displayOptions={{ layout: 'other' }}
            />
          </Card>
          <Card
            overlineText="Compliance results"
            primaryText="Open-source licenses"
            secondaryText="Detected licenses, policy status, and obligations will appear here."
            responsiveWidth
            containerStyle={{ width: '100%' }}
          >
            <EmptyState
              primaryText="No license results yet"
              secondaryText="Results will appear after backend integration."
              displayOptions={{ layout: 'other' }}
            />
          </Card>
        </section>
      </div>
    </DataManagementPage>
  );
}
