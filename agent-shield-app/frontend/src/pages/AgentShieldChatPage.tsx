import { usePage, usePageHeader } from '@idp/nitro-providers';
import { ChatPage } from '../components/v3/ChatPage.js';

export function AgentShieldChatPage() {
  usePage({
    id: 'agent-shield-chat',
    documentTitle: 'Agent Shield Chat',
    layout: 'edgeToEdge',
    showHeader: false,
    pageBackground: false,
  });
  usePageHeader({
    pageTitle: 'Agent Shield Chat',
  });

  return <ChatPage />;
}
