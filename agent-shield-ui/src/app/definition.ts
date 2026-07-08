import type { ComponentType } from 'react';
import { AgentShieldPage } from '../pages/AgentShieldPage.js';
// nitro:page-imports

export interface NitroAppRouteDefinition {
  id: string;
  path: string;
  label: string;
  modulePath: string;
  exportName: string;
  component: ComponentType;
}

export interface NitroGeneratedAppDefinition {
  name: string;
  routes: NitroAppRouteDefinition[];
}

export const appDefinition: NitroGeneratedAppDefinition = {
  name: 'agent-shield-ui',
  routes: [
    {
      id: 'agent-shield',
      path: '/',
      label: 'Agent Shield',
      modulePath: '../pages/AgentShieldPage.js',
      exportName: 'AgentShieldPage',
      component: AgentShieldPage,
    },
    // nitro:routes
  ],
};
