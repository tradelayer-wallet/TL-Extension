// process-polyfill.js
if (typeof process === 'undefined') {
  window.process = {
    env: { NODE_ENV: 'production' }, // You can change this as needed
  };
}
