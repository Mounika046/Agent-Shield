type NitroAppThemeName = 'bluewood' | 'redwood';

const NITRO_APP_THEME_CLASSES = [
  'nitro-theme-bluewood',
  'nitro-theme-redwood',
  'nitro-theme-stable',
];

const NITRO_APP_THEME_PROVIDER_PROPS_BY_THEME = {
  bluewood: {
    theme: 'bluewood',
    colorScheme: 'dark',
    className: 'nitro-app-bluewood-root',
    testId: 'nitro-app-theme-root',
  },
  redwood: {
    theme: 'redwood',
    colorScheme: 'light',
    className: undefined,
    testId: 'nitro-app-theme-root',
  },
} as const;

export function resolveNitroAppThemeName(
  value: string | undefined = import.meta.env.VITE_NITRO_APP_THEME,
): NitroAppThemeName {
  return value?.trim().toLowerCase() === 'bluewood' ? 'bluewood' : 'redwood';
}

export function resolveNitroAppThemeProviderProps(value?: string) {
  return NITRO_APP_THEME_PROVIDER_PROPS_BY_THEME[resolveNitroAppThemeName(value)];
}

export const NITRO_APP_THEME_PROVIDER_PROPS = resolveNitroAppThemeProviderProps();

export function applyNitroAppDocumentTheme(root: HTMLElement) {
  const themeProviderProps = NITRO_APP_THEME_PROVIDER_PROPS;

  root.classList.remove(...NITRO_APP_THEME_CLASSES);
  root.classList.add(`nitro-theme-${themeProviderProps.theme}`);
  root.dataset.nitroTheme = themeProviderProps.theme;
  root.dataset.nitroColorScheme = themeProviderProps.colorScheme;
}
