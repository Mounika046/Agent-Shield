// @nitro-page-template: data-management-page
import { usePage, usePageHeader } from '@idp/nitro-providers';
import { AgentShieldWorkspace } from '../components/AgentShieldWorkspace.js';

export function AgentShieldPage() {
  usePage({
    id: 'agent-shield',
    documentTitle: 'Agent Shield',
    layout: 'edgeToEdge',
    showHeader: false,
    pageBackground: false,
  });
  usePageHeader({
    pageTitle: 'Agent Shield',
  });

  return <AgentShieldWorkspace />;
}
