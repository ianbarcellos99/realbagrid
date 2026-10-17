// Service worker do app Real Bagrid.
// Não guarda cache das páginas: o app sempre carrega a versão mais nova do site.
// As notificações (push) serão tratadas aqui na próxima etapa.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
