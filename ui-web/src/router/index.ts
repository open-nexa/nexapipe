/**
 * The console's routes.
 *
 * A hash router, not a history one: the instance serves the bundle as files
 * and has no rule that rewrites an unknown path to the index, so every path
 * the console needs has to live inside the fragment.
 */
import { createRouter, createWebHashHistory } from 'vue-router';
import OverviewPage from '../pages/OverviewPage.vue';
import RoutesPage from '../pages/RoutesPage.vue';
import ClientsPage from '../pages/ClientsPage.vue';

export default createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', name: 'overview', component: OverviewPage },
    { path: '/routes', name: 'routes', component: RoutesPage },
    { path: '/clients', name: 'clients', component: ClientsPage },
  ],
});
