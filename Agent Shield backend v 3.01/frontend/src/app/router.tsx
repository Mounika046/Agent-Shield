import {
  useApplication,
  useConfiguration,
  useDirtyData,
  usePage,
  usePageHeader,
  useRouting,
} from '@idp/nitro-providers';
import {
  AskOracle,
  AskOracleNavigationList,
  type AskOracleNavigationListItem,
  AskOracleNotifications,
  type AskOraclePageLayout,
  AskOracleProductMap,
  AskOracleSearch,
  AskOracleUserProfile,
  HeaderGeneralOverview,
  MessageUnsavedChanges,
  PillarTheme,
} from '@idp/nitro-redwood';
import {
  Outlet,
  type RouteComponent,
  createHashHistory,
  createRootRoute,
  createRoute,
  createRouter,
  useBlocker,
  useNavigate,
  useRouterState,
} from '@tanstack/react-router';
import { Suspense, useCallback, useEffect, useId, useMemo, useState } from 'react';
import { appDefinition } from './definition.js';

interface DemoConfig {
  ENABLE_ASK_ORACLE?: boolean;
  ENABLE_NOTIFICATIONS?: boolean;
  USER_DISPLAY_NAME?: string;
  AVATAR_INITIALS?: string;
}

const GBU_TEXTURE_START =
  'https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/background-shell-gbus-start.png';
const GBU_TEXTURE_END =
  'https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/background-shell-gbus-end.png';

function useBackgroundTexture(page: ReturnType<typeof usePage>['page']) {
  useEffect(() => {
    const body = document.body;
    const start =
      page.backgroundTextureStart !== undefined ? page.backgroundTextureStart : GBU_TEXTURE_START;
    const end =
      page.backgroundTextureEnd !== undefined ? page.backgroundTextureEnd : GBU_TEXTURE_END;
    if (start != null) {
      body.style.setProperty('--nitro-bg-texture-start', `url("${start}")`);
    } else {
      body.style.removeProperty('--nitro-bg-texture-start');
    }
    if (end != null) {
      body.style.setProperty('--nitro-bg-texture-end', `url("${end}")`);
    } else {
      body.style.removeProperty('--nitro-bg-texture-end');
    }
    return () => {
      body.style.removeProperty('--nitro-bg-texture-start');
      body.style.removeProperty('--nitro-bg-texture-end');
    };
  }, [page.backgroundTextureStart, page.backgroundTextureEnd]);
}

function RouterBridge() {
  const location = useRouterState({ select: (s) => s.location });
  const navigate = useNavigate();
  const { setLocation, setNavigate } = useRouting();

  useEffect(() => {
    setLocation({
      pathname: location.pathname,
      search: location.searchStr,
      hash: location.hash,
    });
  }, [location.pathname, location.searchStr, location.hash, setLocation]);

  useEffect(() => {
    setNavigate((to: string) => {
      navigate({ to });
    });
  }, [navigate, setNavigate]);

  return null;
}

function NitroShell() {
  useApplication();
  const { config } = useConfiguration();
  const demo = config as unknown as DemoConfig;
  const { page } = usePage();
  const { pageHeader } = usePageHeader();
  const navigate = useNavigate();
  const appContainerId = useId();

  const navItems: AskOracleNavigationListItem[] = useMemo(
    () =>
      appDefinition.routes.map((route) => ({
        id: route.path,
        label: route.label,
        icon: 'oj-ux-ico-page-layout',
      })),
    [],
  );

  const productMapItems = useMemo(
    () => [
      {
        id: 'app-home',
        label: appDefinition.name,
        icon: 'oj-ux-ico-application',
        children: appDefinition.routes.map((route) => ({
          id: route.path,
          label: route.label,
          icon: 'oj-ux-ico-page-layout',
          url: route.path,
        })),
      },
    ],
    [],
  );

  const handleProductMapNavigate = useCallback(
    (detail: { url?: string }) => {
      if (!detail.url) return;
      navigate({ to: detail.url });
      setAskOracleExpanded(false);
      setSearchValue('');
    },
    [navigate],
  );

  const [askOracleExpanded, setAskOracleExpanded] = useState(false);
  const [searchValue, setSearchValue] = useState('');

  useBackgroundTexture(page);

  const showHeader = (page.showHeader ?? true) && page.id !== 'home' && !!pageHeader.pageTitle;
  const askOraclePageLayout: AskOraclePageLayout =
    page.id === 'home' ? 'edgeToEdge' : ((page.layout ?? 'fixedWidth') as AskOraclePageLayout);

  const pageBodyClass = useMemo(
    () =>
      ['oj-gbu-page-body', (page.pageBackground ?? true) ? null : 'oj-gbu-page-body--no-background']
        .filter((token): token is string => token != null)
        .join(' '),
    [page.pageBackground],
  );

  const { isDirty, resetAll } = useDirtyData();
  const blocker = useBlocker({ condition: isDirty });
  const [showUnsavedDialog, setShowUnsavedDialog] = useState(false);

  useEffect(() => {
    if (blocker.status === 'blocked') setShowUnsavedDialog(true);
  }, [blocker.status]);

  const handleDiscard = useCallback(() => {
    setShowUnsavedDialog(false);
    resetAll();
    if (blocker.status === 'blocked') blocker.proceed?.();
  }, [blocker, resetAll]);

  const handleCancel = useCallback(() => {
    setShowUnsavedDialog(false);
    if (blocker.status === 'blocked') blocker.reset?.();
  }, [blocker]);

  const handleSearchEnter = useCallback(
    (value: string) => {
      if (value.trim()) {
        setAskOracleExpanded(false);
        setSearchValue('');
      }
    },
    [],
  );

  const handleNavNavigate = useCallback(
    (detail: { data: AskOracleNavigationListItem; metadata: AskOracleNavigationListItem }) => {
      navigate({ to: detail.data.id });
      setAskOracleExpanded(false);
      setSearchValue('');
    },
    [navigate],
  );

  const collapse = useCallback(() => {
    setAskOracleExpanded(false);
    setSearchValue('');
  }, []);

  return (
    <PillarTheme pillar="gbu" mode="light" scale="large">
      <RouterBridge />
      <div
        id={appContainerId}
        className="oj-web-applayout-page nitro-shell-root"
        data-testid="nitro-shell-frame"
      >
        <AskOracle
          expanded={askOracleExpanded}
          searchValue={searchValue}
          pageLayout={askOraclePageLayout}
          onAskOracleExpand={() => setAskOracleExpanded(true)}
          onAskOracleCollapse={collapse}
          askOracleSearch={
            <AskOracleSearch
              value={searchValue}
              placeholder={['"Search pages"', '"Find components"']}
              onValueChange={setSearchValue}
              onSearch={handleSearchEnter}
              onBack={() => setSearchValue('')}
            />
          }
          askOracleNavigation={
            <AskOracleNavigationList
              data={navItems}
              mode="suggestions"
              displayOptions={{ punchOutIcon: true }}
              onNavigate={handleNavNavigate}
            />
          }
          askOracleNotification={
            <AskOracleNotifications data={[]} onAction={() => {}} />
          }
          askOracleUserProfile={
            <AskOracleUserProfile
              userDisplayName={demo.USER_DISPLAY_NAME ?? 'User'}
              avatar={{ initials: demo.AVATAR_INITIALS ?? 'U' }}
              onSignOut={() => {}}
            />
          }
          askOracleCustom={
            <AskOracleProductMap
              items={productMapItems as never[]}
              displayOptions={{ showDescription: true }}
              onNavigate={handleProductMapNavigate}
              onViewAllQuickActions={() => {}}
            />
          }
        >
          <div className={pageBodyClass}>
            {showHeader && (
              <HeaderGeneralOverview
                pageTitle={pageHeader.pageTitle ?? ''}
                pageSubtitle={pageHeader.pageSubtitle}
                avatar={pageHeader.avatar}
                primaryAction={pageHeader.primaryAction}
                secondaryActions={pageHeader.secondaryActions}
                onPrimaryAction={pageHeader.onPrimaryAction ?? undefined}
                onSecondaryAction={pageHeader.onSecondaryAction ?? undefined}
              />
            )}
            <Suspense fallback={<div>Loading…</div>}>
              <Outlet />
            </Suspense>
          </div>
        </AskOracle>
      </div>
      {showUnsavedDialog && (
        <MessageUnsavedChanges
          openDialog={showUnsavedDialog}
          display="discard"
          onDiscardChanges={handleDiscard}
          onCancel={handleCancel}
        />
      )}
    </PillarTheme>
  );
}

const rootRoute = createRootRoute({
  component: NitroShell,
});

const childRoutes = appDefinition.routes.map((route) =>
  createRoute({
    getParentRoute: () => rootRoute,
    path: route.path,
    component: route.component as RouteComponent,
  }),
);

const routeTree = rootRoute.addChildren(childRoutes);

export const router = createRouter({
  routeTree,
  history: createHashHistory(),
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
