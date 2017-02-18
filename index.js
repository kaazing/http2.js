var http = require('./lib/http');
var timers = require('timers');
var setImmediate = require('timers').setImmediate;


websocket = require('websocket-stream');
window.http2 = {};
window.http2.raw = {};
window.http2.raw.request = http.raw.request;
