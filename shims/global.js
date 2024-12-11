// global.js
if (typeof global === 'undefined') {
  window.global = window;
}

if (typeof process === 'undefined') {
  window.process = {
    version: 'v8.0.0',  // Or any version string you'd like to use
  };
}


if (typeof Buffer === 'undefined') {
  console.log('Buffer is undefined, polyfilling...');
  window.Buffer = require('buffer').Buffer;
} else {
  console.log('Buffer is already defined');
}


if (!Function.prototype.call) {
  Function.prototype.call = function() {
    // Fallback logic or just a no-op
    console.warn('Function.call is not defined in this environment.');
  };
}


