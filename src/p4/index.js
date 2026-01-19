import P4 from './P4.svelte';
import serviceWorker from '!!file-loader?name=sw.js!./sw.js';

const app = new P4({
  target: document.getElementById('app')
});

document.body.setAttribute('p4-loaded', '');

if (process.env.STANDALONE && 'serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then(registrations => {
    registrations.forEach(registration => registration.unregister());
  }).catch(() => {});
}

if (process.env.ENABLE_SERVICE_WORKER && !process.env.STANDALONE && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register(serviceWorker)
      .then(() => {
        console.log('SW registered');
      }).catch((error) => {
        console.log('SW error', error);
      });
  });
}
