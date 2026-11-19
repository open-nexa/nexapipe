import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import i18n, { applyDocumentLocale } from './i18n';
import './styles/main.css';

applyDocumentLocale(i18n.global.locale.value);

createApp(App).use(i18n).use(router).mount('#app');
