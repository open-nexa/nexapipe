import { createRouter, createWebHashHistory } from 'vue-router';

/**
 * Hash history, not HTML5 history (§5.10).
 *
 * A packaged Tauri app serves the frontend from a custom scheme with no server behind it, so there
 * is nothing to rewrite `/config` into `index.html`. In hash mode the route lives entirely in the
 * fragment, and a reload — or a window restored at a deep link — always lands back on `index.html`.
 *
 * `meta.titleKey` is a locale key rather than a label: the page header and the sidebar then read
 * the same source and cannot drift apart in either language (§5.5).
 */
const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/',
      name: 'connect',
      component: () => import('../pages/DashboardPage.vue'),
      meta: { titleKey: 'nav.connect' },
    },
    {
      path: '/config',
      name: 'config',
      component: () => import('../pages/ConfigPage.vue'),
      meta: { titleKey: 'nav.config' },
    },
    {
      path: '/settings',
      name: 'settings',
      component: () => import('../pages/SettingsPage.vue'),
      meta: { titleKey: 'nav.settings' },
    },
    {
      path: '/logs',
      name: 'logs',
      component: () => import('../pages/LogsPage.vue'),
      meta: { titleKey: 'nav.logs' },
    },
    {
      // An unknown fragment — a stale bookmark from the history-mode build, a hand-edited URL —
      // lands on Connect rather than on a blank window.
      path: '/:pathMatch(.*)*',
      name: 'not-found',
      redirect: { name: 'connect' },
    },
  ],
});

export default router;
