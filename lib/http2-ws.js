WebSocket = require('websocket-stream');
var env = require('./utils/environment');

if(!env.isNode()){
    require("setimmediate");
}

function http2ws(){

}

var PassThrough = require('readable-stream').PassThrough;
var Readable = require('readable-stream').Readable;
var Writable = require('readable-stream').Writable;
var protocol = require('./protocol');
var Endpoint = protocol.Endpoint;


// var EventEmitter = require('events').EventEmitter;
var indexOf;

if (typeof Array.prototype.indexOf === 'function') {
    indexOf = function (haystack, needle) {
        return haystack.indexOf(needle);
    };
} else {
    indexOf = function (haystack, needle) {
        var i = 0, length = haystack.length, idx = -1, found = false;

        while (i < length && !found) {
            if (haystack[i] === needle) {
                idx = i;
                found = true;
            }

            i++;
        }

        return idx;
    };
};


/* Polyfill EventEmitter. */
var EventEmitter = function () {
    this.events = {};
};

EventEmitter.prototype.on = function (event, listener) {
    if (typeof this.events[event] !== 'object') {
        this.events[event] = [];
    }

    this.events[event].push(listener);
};

EventEmitter.prototype.removeListener = function (event, listener) {
    var idx;

    if (typeof this.events[event] === 'object') {
        idx = indexOf(this.events[event], listener);

        if (idx > -1) {
            this.events[event].splice(idx, 1);
        }
    }
};

EventEmitter.prototype.emit = function (event) {
    var i, listeners, length, args = [].slice.call(arguments, 1);

    if (typeof this.events[event] === 'object') {
        listeners = this.events[event].slice();
        length = listeners.length;

        for (i = 0; i < length; i++) {
            listeners[i].apply(this, args);
        }
    }
};

EventEmitter.prototype.once = function (event, listener) {
    this.on(event, function g () {
        this.removeListener(event, g);
        listener.apply(this, arguments);
    });
};


var statusCodes = {};
statusCodes[exports.ACCEPTED = 202] = "Accepted";
statusCodes[exports.BAD_GATEWAY = 502] = "Bad Gateway";
statusCodes[exports.BAD_REQUEST = 400] = "Bad Request";
statusCodes[exports.CONFLICT = 409] = "Conflict";
statusCodes[exports.CONTINUE = 100] = "Continue";
statusCodes[exports.CREATED = 201] = "Created";
statusCodes[exports.EXPECTATION_FAILED = 417] = "Expectation Failed";
statusCodes[exports.FAILED_DEPENDENCY  = 424] = "Failed Dependency";
statusCodes[exports.FORBIDDEN = 403] = "Forbidden";
statusCodes[exports.GATEWAY_TIMEOUT = 504] = "Gateway Timeout";
statusCodes[exports.GONE = 410] = "Gone";
statusCodes[exports.HTTP_VERSION_NOT_SUPPORTED = 505] = "HTTP Version Not Supported";
statusCodes[exports.INSUFFICIENT_SPACE_ON_RESOURCE = 419] = "Insufficient Space on Resource";
statusCodes[exports.INSUFFICIENT_STORAGE = 507] = "Insufficient Storage";
statusCodes[exports.INTERNAL_SERVER_ERROR = 500] = "Server Error";
statusCodes[exports.LENGTH_REQUIRED = 411] = "Length Required";
statusCodes[exports.LOCKED = 423] = "Locked";
statusCodes[exports.METHOD_FAILURE = 420] = "Method Failure";
statusCodes[exports.METHOD_NOT_ALLOWED = 405] = "Method Not Allowed";
statusCodes[exports.MOVED_PERMANENTLY = 301] = "Moved Permanently";
statusCodes[exports.MOVED_TEMPORARILY = 302] = "Moved Temporarily";
statusCodes[exports.MULTI_STATUS = 207] = "Multi-Status";
statusCodes[exports.MULTIPLE_CHOICES = 300] = "Multiple Choices";
statusCodes[exports.NETWORK_AUTHENTICATION_REQUIRED = 511] = "Network Authentication Required";
statusCodes[exports.NO_CONTENT = 204] = "No Content";
statusCodes[exports.NON_AUTHORITATIVE_INFORMATION = 203] = "Non Authoritative Information";
statusCodes[exports.NOT_ACCEPTABLE = 406] = "Not Acceptable";
statusCodes[exports.NOT_FOUND = 404] = "Not Found";
statusCodes[exports.NOT_IMPLEMENTED = 501] = "Not Implemented";
statusCodes[exports.NOT_MODIFIED = 304] = "Not Modified";
statusCodes[exports.OK = 200] = "OK";
statusCodes[exports.PARTIAL_CONTENT = 206] = "Partial Content";
statusCodes[exports.PAYMENT_REQUIRED = 402] = "Payment Required";
statusCodes[exports.PERMANENT_REDIRECT = 308] = "Permanent Redirect";
statusCodes[exports.PRECONDITION_FAILED = 412] = "Precondition Failed";
statusCodes[exports.PRECONDITION_REQUIRED = 428] = "Precondition Required";
statusCodes[exports.PROCESSING = 102] = "Processing";
statusCodes[exports.PROXY_AUTHENTICATION_REQUIRED = 407] = "Proxy Authentication Required";
statusCodes[exports.REQUEST_HEADER_FIELDS_TOO_LARGE = 431] = "Request Header Fields Too Large";
statusCodes[exports.REQUEST_TIMEOUT = 408] = "Request Timeout";
statusCodes[exports.REQUEST_TOO_LONG = 413] = "Request Entity Too Large";
statusCodes[exports.REQUEST_URI_TOO_LONG = 414] = "Request-URI Too Long";
statusCodes[exports.REQUESTED_RANGE_NOT_SATISFIABLE = 416] = "Requested Range Not Satisfiable";
statusCodes[exports.RESET_CONTENT = 205] = "Reset Content";
statusCodes[exports.SEE_OTHER = 303] = "See Other";
statusCodes[exports.SERVICE_UNAVAILABLE = 503] = "Service Unavailable";
statusCodes[exports.SWITCHING_PROTOCOLS = 101] = "Switching Protocols";
statusCodes[exports.TEMPORARY_REDIRECT = 307] = "Temporary Redirect";
statusCodes[exports.TOO_MANY_REQUESTS = 429] = "Too Many Requests";
statusCodes[exports.UNAUTHORIZED = 401] = "Unauthorized";
statusCodes[exports.UNPROCESSABLE_ENTITY = 422] = "Unprocessable Entity";
statusCodes[exports.UNSUPPORTED_MEDIA_TYPE = 415] = "Unsupported Media Type";
statusCodes[exports.USE_PROXY = 305] = "Use Proxy";

Object.assign = function(target, varArgs) { // .length of function is 2
    'use strict';
    if (target == null) { // TypeError if undefined or null
        throw new TypeError('Cannot convert undefined or null to object');
    }

    var to = Object(target);

    for (var index = 1; index < arguments.length; index++) {
        var nextSource = arguments[index];

        if (nextSource != null) { // Skip over if undefined or null
            for (var nextKey in nextSource) {
                // Avoid bugs when hasOwnProperty is shadowed
                if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
                    to[nextKey] = nextSource[nextKey];
                }
            }
        }
    }
    return to;
};

var deprecatedHeaders = [
    'connection',
    'host',
    'keep-alive',
    'proxy-connection',
    'transfer-encoding',
    'upgrade'
];

http2ws.STATUS_CODES = statusCodes;
// exports.getStatusText = function(statusCode) {
//     if (statusCodes.hasOwnProperty(statusCode)) {
//         return statusCodes[statusCode];
//     } else {
//         throw new Error("Status code does not exist: " + statusCode);
//     }
// };

// Logger shim, used when no logger is provided by the user.
function noop() {}
var defaultLogger = {
    fatal: noop,
    error: noop,
    warn : noop,
    info : noop,
    debug: noop,
    trace: noop,

    child: function() { return this; }
};


// IncomingRequest class
// ---------------------

function IncomingRequest(stream) {
    IncomingMessage.call(this, stream);
}
IncomingRequest.prototype = Object.create(IncomingMessage.prototype, { constructor: { value: IncomingRequest } });

// [Request Header Fields](https://tools.ietf.org/html/rfc7540#section-8.1.2.3)
// * `headers` argument: HTTP/2.0 request and response header fields carry information as a series
//   of key-value pairs. This includes the target URI for the request, the status code for the
//   response, as well as HTTP header fields.
IncomingRequest.prototype._onHeaders = function _onHeaders(headers) {
    // * The ":method" header field includes the HTTP method
    // * The ":scheme" header field includes the scheme portion of the target URI
    // * The ":authority" header field includes the authority portion of the target URI
    // * The ":path" header field includes the path and query parts of the target URI.
    //   This field MUST NOT be empty; URIs that do not contain a path component MUST include a value
    //   of '/', unless the request is an OPTIONS request for '*', in which case the ":path" header
    //   field MUST include '*'.
    // * All HTTP/2.0 requests MUST include exactly one valid value for all of these header fields. A
    //   server MUST treat the absence of any of these header fields, presence of multiple values, or
    //   an invalid value as a stream error of type PROTOCOL_ERROR.
    this.method = this._checkSpecialHeader(':method'   , headers[':method']);
    this.scheme = this._checkSpecialHeader(':scheme'   , headers[':scheme']);
    this.host   = this._checkSpecialHeader(':authority', headers[':authority']  );
    this.url    = this._checkSpecialHeader(':path'     , headers[':path']  );
    if (!this.method || !this.scheme || !this.host || !this.url) {
        // This is invalid, and we've sent a RST_STREAM, so don't continue processing
        return;
    }

    // * Host header is included in the headers object for backwards compatibility.
    this.headers.host = this.host;

    // * Handling regular headers.
    IncomingMessage.prototype._onHeaders.call(this, headers);

    // * Signaling that the headers arrived.
    this._log.info({ method: this.method, scheme: this.scheme, host: this.host,
        path: this.url, headers: this.headers }, 'Incoming request');
    this.emit('ready');
};

// OutgoingResponse class
// ----------------------

function OutgoingResponse(stream) {
    OutgoingMessage.call(this);

    this._log = stream._log.child({ component: 'http' });

    this.stream = stream;
    this.statusCode = 200;
    this.sendDate = true;

    this.stream.once('headers', this._onRequestHeaders.bind(this));
}
OutgoingResponse.prototype = Object.create(OutgoingMessage.prototype, { constructor: { value: OutgoingResponse } });

OutgoingResponse.prototype.writeHead = function writeHead(statusCode, reasonPhrase, headers) {
    if (this.headersSent) {
        return;
    }

    if (typeof reasonPhrase === 'string') {
        this._log.warn('Reason phrase argument was present but ignored by the writeHead method');
    } else {
        headers = reasonPhrase;
    }

    for (var name in headers) {
        this.setHeader(name, headers[name]);
    }
    headers = this._headers;

    if (this.sendDate && !('date' in this._headers)) {
        headers.date = (new Date()).toUTCString();
    }

    this._log.info({ status: statusCode, headers: this._headers }, 'Sending server response');

    headers[':status'] = this.statusCode = statusCode;

    this.stream.headers(headers);
    this.headersSent = true;
};

OutgoingResponse.prototype._implicitHeaders = function _implicitHeaders() {
    if (!this.headersSent) {
        this.writeHead(this.statusCode);
    }
};

OutgoingResponse.prototype._implicitHeader = function() {
    this._implicitHeaders();
};

OutgoingResponse.prototype.write = function write() {
    this._implicitHeaders();
    return OutgoingMessage.prototype.write.apply(this, arguments);
};

OutgoingResponse.prototype.end = function end() {
    this.finshed = true;
    this._implicitHeaders();
    return OutgoingMessage.prototype.end.apply(this, arguments);
};

OutgoingResponse.prototype._onRequestHeaders = function _onRequestHeaders(headers) {
    this._requestHeaders = headers;
};

OutgoingResponse.prototype.push = function push(options) {
    if (typeof options === 'string') {
        options = url.parse(options);
    }

    if (!options.path) {
        throw new Error('`path` option is mandatory.');
    }

    var promise = util._extend({
        ':method': (options.method || 'GET').toUpperCase(),
        ':scheme': (options.protocol && options.protocol.slice(0, -1)) || this._requestHeaders[':scheme'],
        ':authority': options.hostname || options.host || this._requestHeaders[':authority'],
        ':path': options.path
    }, options.headers);

    this._log.info({ method: promise[':method'], scheme: promise[':scheme'],
        authority: promise[':authority'], path: promise[':path'],
        headers: options.headers }, 'Promising push stream');

    var pushStream = this.stream.promise(promise);

    return new OutgoingResponse(pushStream);
};

OutgoingResponse.prototype.altsvc = function altsvc(host, port, protocolID, maxAge, origin) {
    if (origin === undefined) {
        origin = "";
    }
    this.stream.altsvc(host, port, protocolID, maxAge, origin);
};

// Overriding `EventEmitter`'s `on(event, listener)` method to forward certain subscriptions to
// `request`. See `Server.prototype.on` for explanation.
OutgoingResponse.prototype.on = function on(event, listener) {
    if (this.request && (event === 'timeout')) {
        this.request.on(event, listener && listener.bind(this));
    } else {
        OutgoingMessage.prototype.on.call(this, event, listener);
    }
};


// Bunyan serializers exported by submodules that are worth adding when creating a logger.
exports.serializers = protocol.serializers;

// IncomingMessage class
// ---------------------

function IncomingMessage(stream) {
    // * This is basically a read-only wrapper for the [Stream](protocol/stream.html) class.
    PassThrough.call(this);
    stream.pipe(this);
    this.socket = this.stream = stream;

    this._log = stream._log.child({ component: 'http' });

    // * HTTP/2.0 does not define a way to carry the version identifier that is included in the
    //   HTTP/1.1 request/status line. Version is always 2.0.
    this.httpVersion = '2.0';
    this.httpVersionMajor = 2;
    this.httpVersionMinor = 0;

    // * `this.headers` will store the regular headers (and none of the special colon headers)
    this.headers = {};
    this.trailers = undefined;
    this._lastHeadersSeen = undefined;

    // * Other metadata is filled in when the headers arrive.
    stream.once('headers', this._onHeaders.bind(this));
    stream.once('end', this._onEnd.bind(this));
}
IncomingMessage.prototype = Object.create(PassThrough.prototype, { constructor: { value: IncomingMessage } });

// [Request Header Fields](https://tools.ietf.org/html/rfc7540#section-8.1.2.3)
// * `headers` argument: HTTP/2.0 request and response header fields carry information as a series
//   of key-value pairs. This includes the target URI for the request, the status code for the
//   response, as well as HTTP header fields.
IncomingMessage.prototype._onHeaders = function _onHeaders(headers) {
    // * Detects malformed headers
    this._validateHeaders(headers);

    // * Store the _regular_ headers in `this.headers`
    for (var name in headers) {
        if (name[0] !== ':') {
            if (name === 'set-cookie' && !Array.isArray(headers[name])) {
                this.headers[name] = [headers[name]];
            } else {
                this.headers[name] = headers[name];
            }
        }
    }

    // * The last header block, if it's not the first, will represent the trailers
    var self = this;
    this.stream.on('headers', function(headers) {
        self._lastHeadersSeen = headers;
    });
};

IncomingMessage.prototype._onEnd = function _onEnd() {
    this.trailers = this._lastHeadersSeen;
};

IncomingMessage.prototype.setTimeout = noop;

IncomingMessage.prototype._checkSpecialHeader = function _checkSpecialHeader(key, value) {
    if ((typeof value !== 'string') || (value.length === 0)) {
        this._log.error({ key: key, value: value }, 'Invalid or missing special header field');
        this.stream.reset('PROTOCOL_ERROR');
    }

    return value;
};

IncomingMessage.prototype._validateHeaders = function _validateHeaders(headers) {
    // * An HTTP/2.0 request or response MUST NOT include any of the following header fields:
    //   Connection, Host, Keep-Alive, Proxy-Connection, Transfer-Encoding, and Upgrade. A server
    //   MUST treat the presence of any of these header fields as a stream error of type
    //   PROTOCOL_ERROR.
    //  If the TE header is present, it's only valid value is 'trailers'
    for (var i = 0; i < deprecatedHeaders.length; i++) {
        var key = deprecatedHeaders[i];
        if (key in headers || (key === 'te' && headers[key] !== 'trailers')) {
            this._log.error({ key: key, value: headers[key] }, 'Deprecated header found');
            this.stream.reset('PROTOCOL_ERROR');
            return;
        }
    }

    for (var headerName in headers) {
        // * Empty header name field is malformed
        if (headerName.length <= 1) {
            this.stream.reset('PROTOCOL_ERROR');
            return;
        }
        // * A request or response containing uppercase header name field names MUST be
        //   treated as malformed (Section 8.1.3.5). Implementations that detect malformed
        //   requests or responses need to ensure that the stream ends.
        if(/[A-Z]/.test(headerName)) {
            this.stream.reset('PROTOCOL_ERROR');
            return;
        }
    }
};

// OutgoingMessage class
// ---------------------

function OutgoingMessage() {
    // * This is basically a read-only wrapper for the [Stream](protocol/stream.html) class.
    Writable.call(this);

    this._headers = {};
    this._trailers = undefined;
    this.headersSent = false;
    this.finished = false;

    this.on('finish', this._finish);
}
OutgoingMessage.prototype = Object.create(Writable.prototype, { constructor: { value: OutgoingMessage } });

OutgoingMessage.prototype._write = function _write(chunk, encoding, callback) {
    if (this.stream) {
        this.stream.write(chunk, encoding, callback);
    } else {
        this.once('socket', this._write.bind(this, chunk, encoding, callback));
    }
};

OutgoingMessage.prototype._finish = function _finish() {
    if (this.stream) {
        if (this._trailers) {
            if (this.request) {
                this.request.addTrailers(this._trailers);
            } else {
                this.stream.headers(this._trailers);
            }
        }
        this.finished = true;
        this.stream.end();
    } else {
        this.once('socket', this._finish.bind(this));
    }
};

OutgoingMessage.prototype.setHeader = function setHeader(name, value) {
    if (this.headersSent) {
        return this.emit('error', new Error('Can\'t set headers after they are sent.'));
    } else {
        name = name.toLowerCase();
        if (deprecatedHeaders.indexOf(name) !== -1) {
            return this.emit('error', new Error('Cannot set deprecated header: ' + name));
        }
        this._headers[name] = value;
    }
};

OutgoingMessage.prototype.removeHeader = function removeHeader(name) {
    if (this.headersSent) {
        return this.emit('error', new Error('Can\'t remove headers after they are sent.'));
    } else {
        delete this._headers[name.toLowerCase()];
    }
};

OutgoingMessage.prototype.getHeader = function getHeader(name) {
    return this._headers[name.toLowerCase()];
};

OutgoingMessage.prototype.addTrailers = function addTrailers(trailers) {
    this._trailers = trailers;
};

OutgoingMessage.prototype.setTimeout = noop;

OutgoingMessage.prototype._checkSpecialHeader = IncomingMessage.prototype._checkSpecialHeader;


// Client side
// ===========

exports.ClientRequest = OutgoingRequest; // for API compatibility
exports.OutgoingRequest = OutgoingRequest;
exports.IncomingResponse = IncomingResponse;
exports.Agent = Agent;
exports.globalAgent = undefined;

function requestRaw(options, callback) {
    if (typeof options === "string") {
        options = url.parse(options);
    }
    options.plain = true;
    if (options.protocol && options.protocol !== "http:") {
        throw new Error('This interface only supports http-schemed URLs');
    }
    if (options.agent && typeof(options.agent.request) === 'function') {
        var agentOptions = Object.assign({}, options);
        delete agentOptions.agent;
        return options.agent.request(agentOptions, callback);
    }
    return exports.globalAgent.request(options, callback);
}

function getRaw(options, callback) {
    // TODO maybe handle string URL
    // if (typeof options === "string") {
    //     options = url.parse(options);
    // }
    options.plain = true;
    if (options.agent && typeof(options.agent.get) === 'function') {
        var agentOptions = Object.assign({}, options);
        delete agentOptions.agent;
        return options.agent.get(agentOptions, callback);
    }
    return exports.globalAgent.get(options, callback);
}

// Agent class
// -----------

function Agent(options) {
    EventEmitter.call(this);
    // this.setMaxListeners(0);

    options = Object.assign({}, options);

    this._settings = options.settings;
    this._log = (options.log || defaultLogger).child({ component: 'http' });
    this.endpoints = {};

    // * Using an own HTTPS agent, because the global agent does not look at `NPN/ALPNProtocols` when
    //   generating the key identifying the connection, so we may get useless non-negotiated TLS
    //   channels even if we ask for a negotiated one. This agent will contain only negotiated
    //   channels.
    // DPW TODO
    // this._httpsAgent = new https.Agent(options);
    //
    // this.sockets = this._httpsAgent.sockets;
    // this.requests = this._httpsAgent.requests;

    // this.sockets  = new WebSocket('ws://localhost:8080/echo', 'http2');
}
Agent.prototype = Object.create(EventEmitter.prototype, { constructor: { value: Agent } });

Agent.prototype.request = function request(options, callback) {
    if (typeof options === 'string') {
        options = url.parse(options);
    } else {
        options = Object.assign({}, options);
    }

    options.method = (options.method || 'GET').toUpperCase();
    options.protocol = options.protocol || 'http:';
    options.host = options.hostname || options.host || 'localhost';
    options.port = options.port || 443;
    options.path = options.path || '/';

    if (!options.plain && options.protocol === 'http:') {
        this._log.error('Trying to negotiate client request with Upgrade from HTTP/1.1');
        this.emit('error', new Error('HTTP1.1 -> HTTP2 upgrade is not yet supported.'));
    }

    var request = new OutgoingRequest(this._log);

    if (callback) {
        request.on('response', callback);
    }

    var key = [
        !!options.plain,
        options.host,
        options.port
    ].join(':');
    var self = this;

    // * There's an existing HTTP/2 connection to this host
    if (key in this.endpoints) {
        var endpoint = this.endpoints[key];
        request._start(endpoint.createStream(), options);
    }

    // * HTTP/2 over plain WS
    else if (options.plain) {
        endpoint = new Endpoint(this._log, 'CLIENT', this._settings);
        var wsUrl = options.transport;
        // TODO throw error earlier if not defined.
        endpoint.socket = new WebSocket(wsUrl);

        // endpoint.socket = net.connect({
        //     host: options.host,
        //     port: options.port,
        //     localAddress: options.localAddress
        // });

        endpoint.socket.on('error', function (error) {
            self._log.error('Socket error: ' + error.toString());
            request.emit('error', error);
        });

        endpoint.on('error', function(error){
            self._log.error('Connection error: ' + error.toString());
            request.emit('error', error);
        });

        this.endpoints[key] = endpoint;
        endpoint.pipe(endpoint.socket).pipe(endpoint);
        request._start(endpoint.createStream(), options);
    }

    return request;
};

Agent.prototype.get = function get(options, callback) {
    var request = this.request(options, callback);
    request.end();
    return request;
};

Agent.prototype.destroy = function(error) {
    // DPW TODO _httpsAgent?
    if (this._httpsAgent) {
        this._httpsAgent.destroy();
    }
    for (var key in this.endpoints) {
        this.endpoints[key].close(error);
    }
};

function unbundleSocket(socket) {
    socket.removeAllListeners('data');
    socket.removeAllListeners('end');
    socket.removeAllListeners('readable');
    socket.removeAllListeners('close');
    socket.removeAllListeners('error');
    socket.unpipe();
    delete socket.ondata;
    delete socket.onend;
}

function hasAgentOptions(options) {
    return options.pfx != null ||
        options.key != null ||
        options.passphrase != null ||
        options.cert != null ||
        options.ca != null ||
        options.ciphers != null ||
        options.rejectUnauthorized != null ||
        options.secureProtocol != null;
}

// DPW TODO +httpsAgent?
Object.defineProperty(Agent.prototype, 'maxSockets', {
    get: function getMaxSockets() {
        return this._httpsAgent.maxSockets;
    },
    set: function setMaxSockets(value) {
        this._httpsAgent.maxSockets = value;
    }
});

exports.globalAgent = new Agent();

// OutgoingRequest class
// ---------------------

function OutgoingRequest() {
    OutgoingMessage.call(this);

    this._log = undefined;

    this.stream = undefined;
}
OutgoingRequest.prototype = Object.create(OutgoingMessage.prototype, { constructor: { value: OutgoingRequest } });

OutgoingRequest.prototype._start = function _start(stream, options) {
    this.stream = stream;
    this.options = options;

    this._log = stream._log.child({ component: 'http' });

    for (var key in options.headers) {
        this.setHeader(key, options.headers[key]);
    }
    var headers = this._headers;
    delete headers.host;

    if (options.auth) {
        headers.authorization = 'Basic ' + new Buffer(options.auth).toString('base64');
    }

    headers[':scheme'] = options.protocol.slice(0, -1);
    headers[':method'] = options.method;
    headers[':authority'] = options.host;
    headers[':path'] = options.path;

    this._log.info({ scheme: headers[':scheme'], method: headers[':method'],
        authority: headers[':authority'], path: headers[':path'],
        headers: (options.headers || {}) }, 'Sending request');
    this.stream.headers(headers);
    this.headersSent = true;

    this.emit('socket', this.stream);
    var response = new IncomingResponse(this.stream);
    response.req = this;
    response.once('ready', this.emit.bind(this, 'response', response));

    this.stream.on('promise', this._onPromise.bind(this));
};

OutgoingRequest.prototype._fallback = function _fallback(request) {
    request.on('response', this.emit.bind(this, 'response'));
    this.stream = this.request = request;
    this.emit('socket', this.socket);
};

OutgoingRequest.prototype.setPriority = function setPriority(priority) {
    if (this.stream) {
        this.stream.priority(priority);
    } else {
        this.once('socket', this.setPriority.bind(this, priority));
    }
};

// Overriding `EventEmitter`'s `on(event, listener)` method to forward certain subscriptions to
// `request`. See `Server.prototype.on` for explanation.
OutgoingRequest.prototype.on = function on(event, listener) {
    if (this.request && (event === 'upgrade')) {
        this.request.on(event, listener && listener.bind(this));
    } else {
        OutgoingMessage.prototype.on.call(this, event, listener);
    }
};

// Methods only in fallback mode
OutgoingRequest.prototype.setNoDelay = function setNoDelay(noDelay) {
    if (this.request) {
        this.request.setNoDelay(noDelay);
    } else if (!this.stream) {
        this.on('socket', this.setNoDelay.bind(this, noDelay));
    }
};

OutgoingRequest.prototype.setSocketKeepAlive = function setSocketKeepAlive(enable, initialDelay) {
    if (this.request) {
        this.request.setSocketKeepAlive(enable, initialDelay);
    } else if (!this.stream) {
        this.on('socket', this.setSocketKeepAlive.bind(this, enable, initialDelay));
    }
};

OutgoingRequest.prototype.setTimeout = function setTimeout(timeout, callback) {
    if (this.request) {
        this.request.setTimeout(timeout, callback);
    } else if (!this.stream) {
        this.on('socket', this.setTimeout.bind(this, timeout, callback));
    }
};

// Aborting the request
OutgoingRequest.prototype.abort = function abort() {
    if (this.request) {
        this.request.abort();
    } else if (this.stream) {
        this.stream.reset('CANCEL');
    } else {
        this.on('socket', this.abort.bind(this));
    }
};

// Receiving push promises
OutgoingRequest.prototype._onPromise = function _onPromise(stream, headers) {
    this._log.info({ push_stream: stream.id }, 'Receiving push promise');

    var promise = new IncomingPromise(stream, headers);

    if (this.listeners('push').length > 0) {
        this.emit('push', promise);
    } else {
        promise.cancel();
    }
};

// IncomingResponse class
// ----------------------

function IncomingResponse(stream) {
    IncomingMessage.call(this, stream);
}
IncomingResponse.prototype = Object.create(IncomingMessage.prototype, { constructor: { value: IncomingResponse } });

// [Response Header Fields](https://tools.ietf.org/html/rfc7540#section-8.1.2.4)
// * `headers` argument: HTTP/2.0 request and response header fields carry information as a series
//   of key-value pairs. This includes the target URI for the request, the status code for the
//   response, as well as HTTP header fields.
IncomingResponse.prototype._onHeaders = function _onHeaders(headers) {
    // * A single ":status" header field is defined that carries the HTTP status code field. This
    //   header field MUST be included in all responses.
    // * A client MUST treat the absence of the ":status" header field, the presence of multiple
    //   values, or an invalid value as a stream error of type PROTOCOL_ERROR.
    //   Note: currently, we do not enforce it strictly: we accept any format, and parse it as int
    // * HTTP/2.0 does not define a way to carry the reason phrase that is included in an HTTP/1.1
    //   status line.
    this.statusCode = parseInt(this._checkSpecialHeader(':status', headers[':status']));

    // * Handling regular headers.
    IncomingMessage.prototype._onHeaders.call(this, headers);

    // * Signaling that the headers arrived.
    this._log.info({ status: this.statusCode, headers: this.headers}, 'Incoming response');
    this.emit('ready');
};

// IncomingPromise class
// -------------------------

function IncomingPromise(responseStream, promiseHeaders) {
    var stream = new Readable();
    stream._read = noop;
    stream.push(null);
    stream._log = responseStream._log;

    IncomingRequest.call(this, stream);

    this._onHeaders(promiseHeaders);

    this._responseStream = responseStream;

    var response = new IncomingResponse(this._responseStream);
    response.once('ready', this.emit.bind(this, 'response', response));

    this.stream.on('promise', this._onPromise.bind(this));
}
IncomingPromise.prototype = Object.create(IncomingRequest.prototype, { constructor: { value: IncomingPromise } });

IncomingPromise.prototype.cancel = function cancel() {
    this._responseStream.reset('CANCEL');
};

IncomingPromise.prototype.setPriority = function setPriority(priority) {
    this._responseStream.priority(priority);
};

IncomingPromise.prototype._onPromise = OutgoingRequest.prototype._onPromise;

exports.Agent = Agent;
exports.get = getRaw;

// If browser then attach to window
if (!env.isNode()) {
    // DPW TODO, combine with node export logic
    window.http2ws = http2ws;
    http2ws.get = getRaw;
}