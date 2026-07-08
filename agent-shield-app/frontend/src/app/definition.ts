import type { ComponentType } from 'react';
import { AgentShieldPage } from '../pages/AgentShieldPage.js';
import { AgentShieldChatPage } from '../pages/AgentShieldChatPage.js';
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
    {
      id: 'agent-shield-chat',
      path: '/chat',
      label: 'Agent Chat',
      modulePath: '../pages/AgentShieldChatPage.js',
      exportName: 'AgentShieldChatPage',
      component: AgentShieldChatPage,
    },
    // nitro:routes
  ],
};
