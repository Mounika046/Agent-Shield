import { defaultEnabledProviders, NitroProviders } from '@idp/nitro-providers';
import { createRoot } from 'react-dom/client';
import { applyNitroAppDocumentTheme, NITRO_APP_THEME_PROVIDER_PROPS } from './app-theme.js';
import { AgentShieldPage } from './pages/AgentShieldPage.js';
import './styles/globals.css';

const defaultConfig = {
  developerId: 'nitro',
  prefix: 'idp',
  ENABLE_ASK_ORACLE: true,
  ENABLE_NOTIFICATIONS: true,
  USER_DISPLAY_NAME: 'Demo User',
  AVATAR_INITIALS: 'DU',
};

applyNitroAppDocumentTheme(document.documentElement);

createRoot(document.getElementById('app') as HTMLElement).render(
  <NitroProviders
    enabledProviders={[
      ...defaultEnabledProviders,
      'AuthProvider',
      'DirtyDataProvider',
    ]}
    providersProps={{
      ConfigurationProvider: {
        defaultConfig,
      },
      ThemeProvider: NITRO_APP_THEME_PROVIDER_PROPS,
    }}
  >
    <AgentShieldPage />
  </NitroProviders>,
);
