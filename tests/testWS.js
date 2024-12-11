const WebSocket = require('ws');
const ws = new WebSocket('wss://api.sidepit.com:12121');

ws.on('open', function open() {
  console.log('connected');
});

ws.on('message', function incoming(data) {
  console.log('received: %s', data);
});

ws.on('error', function error(error) {
  console.error('WebSocket error:', error);
});

ws.on('close', function close() {
  console.log('connection closed');
});
