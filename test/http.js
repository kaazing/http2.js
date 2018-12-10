/* global __dirname */
var expect = require('chai').expect;
var util = require('./util');
var fs = require('fs');
var path = require('path');
var url = require('url');
var net = require('net');

var http2 = require('../lib/http');
var https = require('https');
var http = require('http');
var websocket = require('websocket-stream');
var pako = require('pako');

var serverOptions = {
  key: fs.readFileSync(path.join(__dirname, '../example/localhost.key')),
  cert: fs.readFileSync(path.join(__dirname, '../example/localhost.crt')),
  rejectUnauthorized: true,
  log: util.serverLog
};

var agentOptions = {
  key: serverOptions.key,
  ca: serverOptions.cert,
  rejectUnauthorized: true,
  log: util.clientLog
};

var globalAgent = new http2.Agent(agentOptions);

describe('http.js', function() {
  beforeEach(function() {
    http2.globalAgent = globalAgent;
  });
  describe('Server', function() {
    describe('new Server(options)', function() {
      it('should throw if called without \'plain\' or TLS options', function() {
        expect(function() {
          return new http2.Server();
        }).to.throw(Error);
        expect(function() {
          http2.createServer(util.noop);
        }).to.throw(Error);
      });
    });
    describe('method `listen()`', function () {
      it('should emit `listening` event', function (done) {
        var server = http2.createServer(serverOptions);

        server.on('listening', function () {
          server.close();

          done();
        });

        server.listen(0);
      });
      it('should emit `error` on failure', function (done) {
        var server = http2.createServer(serverOptions);

        // This TCP server is used to explicitly take a port to make
        // server.listen() fails.
        var net = require('net').createServer();

        server.on('error', function () {
          net.close();
          done();
        });

        net.listen(0, function () {
          server.listen(this.address().port);
        });
      });
    });
    describe('property `timeout`', function() {
      it('should be a proxy for the backing HTTPS server\'s `timeout` property', function() {
        var server = new http2.Server(serverOptions);
        var backingServer = server._server;
        var newTimeout = 10;
        server.timeout = newTimeout;
        expect(server.timeout).to.be.equal(newTimeout);
        expect(backingServer.timeout).to.be.equal(newTimeout);
      });
    });
    describe('method `setTimeout(timeout, [callback])`', function() {
      it('should be a proxy for the backing HTTPS server\'s `setTimeout` method', function() {
        var server = new http2.Server(serverOptions);
        var backingServer = server._server;
        var newTimeout = 10;
        var newCallback = util.noop;
        backingServer.setTimeout = function(timeout, callback) {
          expect(timeout).to.be.equal(newTimeout);
          expect(callback).to.be.equal(newCallback);
        };
        server.setTimeout(newTimeout, newCallback);
      });
    });
  });

  function generateRandAlphaNumStr(len) {
      var rdmString = "";
      while (rdmString.length < len) {
          rdmString += Math.random().toString(36).substr(2);
      }
      return rdmString;
  }

  describe('should accept-encoding gzip', function() {
      
      it('does a request and gets a response with gzip encoding', function (done) {
          var path = '/x';
          var message = 'Hello world';

          var compressedMessage = pako.gzip(message);

          compressedMessage = Buffer.from(compressedMessage.buffer);
          var server = http2.createServer(serverOptions, function (request, response) {
              expect(request.url).to.equal(path);
              response.setHeader('content-encoding', 'gzip');
              var chunk1 = Buffer.from(compressedMessage, 0, 15);
              response.write(chunk1);
              response.write(Buffer.from(compressedMessage, 0, 0));
              var chunk2 = Buffer.from(compressedMessage, 15);
              response.write(chunk2);
              response.end();
          });

          server.listen(1244, function () {
              var options = url.parse('https://localhost:1244' + path);
              options.key = agentOptions.key;
              options.ca = agentOptions.ca;
              options.rejectUnauthorized = true;

              http2.globalAgent = new http2.Agent({log: util.clientLog});
              http2.get(options, function (response) {
                  response.on('data', function (data) {
                      expect(data.toString()).to.equal(message);
                      server.close();
                      done();
                  });
              });
          });
      });

      it('does a request and gets a response with gzip encoding for response larger than MAX_PAYLOAD_SIZE', function (done) {
          var path = '/x';
          var message = generateRandAlphaNumStr(4096);
          var compressedMessage = pako.gzip(message);
          compressedMessage = Buffer.from(compressedMessage.buffer);
          var server = http2.createServer(serverOptions, function (request, response) {
              expect(request.url).to.equal(path);
              response.setHeader('content-encoding', 'gzip');
              var chunk1 = Buffer.from(compressedMessage, 0, 15);
              response.write(chunk1);
              response.write(Buffer.from(compressedMessage, 0, 0));
              var chunk2 = Buffer.from(compressedMessage, 15);
              response.write(chunk2);
              response.end();
          });

          server.listen(1244, function () {
              var options = url.parse('https://localhost:1244' + path);
              options.key = agentOptions.key;
              options.ca = agentOptions.ca;
              options.rejectUnauthorized = true;

              http2.globalAgent = new http2.Agent({log: util.clientLog});
              http2.get(options, function (response) {
                  response.on('data', function (data) {
                      expect(data.toString().length).to.equal(message.length);
                      expect(data.toString()).to.equal(message);
                      server.close();
                      done();
                  });
              });
          });
      });

      it('does a request and gets a response with gzip encoding for response larger than MAX_PAYLOAD_SIZE', function (done) {
          var path = '/x';
          // TODO validate this test is not false positive or memory limit
          // use larger than MAX_PAYLOAD_SIZE > 3 make that test fail
          // Lines        : 89.51% ( 1972/2203 ) vs Lines        : 89.61% ( 1974/2203 )
          var message = generateRandAlphaNumStr(4096 * 3); 
          var compressedMessage = pako.gzip(message);
          compressedMessage = Buffer.from(compressedMessage.buffer);
          var server = http2.createServer(serverOptions, function (request, response) {
              expect(request.url).to.equal(path);
              response.setHeader('content-encoding', 'gzip');
              var chunk1 = Buffer.from(compressedMessage, 0, 15);
              response.write(chunk1);
              response.write(Buffer.from(compressedMessage, 0, 0));
              var chunk2 = Buffer.from(compressedMessage, 15);
              response.write(chunk2);
              response.end();
          });

          server.listen(1244, function () {
              var options = url.parse('https://localhost:1244' + path);
              options.key = agentOptions.key;
              options.ca = agentOptions.ca;
              options.rejectUnauthorized = true;

              http2.globalAgent = new http2.Agent({log: util.clientLog});
              http2.get(options, function (response) {
                  response.on('data', function (data) {
                      expect(data.toString().length).to.equal(message.length);
                      expect(data.toString()).to.equal(message);
                      server.close();
                      done();
                  });
              });
          });
      });
  });

  describe('should handle retry-after on statusCode 503', function () {

    it('does a request and gets a response for statusCode 503 without `retry-after` header', function (done) {
      var path = '/retry-later';
      var errorMessage = 'Service is NOT available';

      var server = http2.createServer(serverOptions, function (request, response) {
        var requestDate = Date.now();
          expect(request.url).to.equal(path);

          // DEBUG:
          //console.log('request', request.url, requestDate, restartDate, requestDate < restartDate);

          response.writeHead(503);
          response.write(errorMessage);
          response.end(); 
      });

      server.listen(1244, function () {
          var options = url.parse('https://localhost:1244' + path);
          options.key = agentOptions.key;
          options.ca = agentOptions.ca;
          options.rejectUnauthorized = true;

          http2.globalAgent = new http2.Agent({log: util.clientLog});
          http2.get(options, function (response) {

              // DEBUG:
              //console.log('response', response.statusCode);
              
              expect(response.statusCode).to.equal(503);
              
              response.on('data', function (data) {
                  // TODO
                  expect(data.toString()).to.equal(errorMessage);
              });

              response.on('end',function(){
                // WHY finished undefined ?
                //expect(response.finished).to.equal(true);
                server.close();
                done();
              });
          });
      });
    });

    it('does a request and gets a response for statusCode 503 without `retry-after` header with gzip encoding', function (done) {
      var path = '/retry-later';
      var errorMessage = 'Service is NOT available';

      var compressedErrorMessage = pako.gzip(errorMessage);
      compressedErrorMessage = Buffer.from(compressedErrorMessage.buffer);

      var server = http2.createServer(serverOptions, function (request, response) {
        var requestDate = Date.now();
          expect(request.url).to.equal(path);

          // DEBUG:
          //console.log('request', request.url, requestDate, restartDate, requestDate < restartDate);
          response.setHeader('content-encoding', 'gzip');
          response.writeHead(503);

          var chunk1 = Buffer.from(compressedErrorMessage, 0, 15);
          response.write(chunk1);
          response.write(Buffer.from(compressedErrorMessage, 0, 0));
          var chunk2 = Buffer.from(compressedErrorMessage, 15);
          response.write(chunk2);
          response.end();

      });

      server.listen(1244, function () {
          var options = url.parse('https://localhost:1244' + path);
          options.key = agentOptions.key;
          options.ca = agentOptions.ca;
          options.rejectUnauthorized = true;

          http2.globalAgent = new http2.Agent({log: util.clientLog});
          http2.get(options, function (response) {

              // DEBUG:
              //console.log('response', response.statusCode);
              
              expect(response.statusCode).to.equal(503);
              
              response.on('data', function (data) {
                  // TODO
                  expect(data.toString()).to.equal(errorMessage);
              });

              response.on('end',function(){
                // WHY finished undefined ?
                //expect(response.finished).to.equal(true);
                server.close();
                done();
              });
          });
      });
    });

    it('does a request and gets a response statusCode 200 with `retry-after` = 0 header in seconds and statusCode 503', function (done) {
      var path = '/retry-later';
      var errorMessage = 'Service is NOT available';
      var message = 'Hello Dave I\'m back';

      var nbRequest = 0;
      var server = http2.createServer(serverOptions, function (request, response) {
          nbRequest++;
          expect(request.url).to.equal(path);

          // DEBUG:
          //console.log('request', request.url, requestDate, restartDate, requestDate < restartDate);
          if (nbRequest === 1) {
            response.setHeader('retry-after', 0);
            response.writeHead(503);
            response.write(errorMessage); 
          } else {
            response.writeHead(200);
            response.write(message);
          }
          response.end(); 
      });

      server.listen(1244, function () {
          var options = url.parse('https://localhost:1244' + path);
          options.key = agentOptions.key;
          options.ca = agentOptions.ca;
          options.rejectUnauthorized = true;

          http2.globalAgent = new http2.Agent({log: util.clientLog});
          http2.get(options, function (response) {

              // DEBUG:
              //console.log('response', response.statusCode);
              
              expect(response.statusCode).to.equal(200);
              
              response.on('data', function (data) {
                  // TODO
                  expect(nbRequest).to.equal(2);
                  expect(data.toString()).to.equal(message);
              });

              response.on('end',function(){
                // WHY finished undefined ?
                //expect(response.finished).to.equal(true);
                server.close();
                done();
              });
          });
      });
    });

    it('does a request and gets a response statusCode 200 with `retry-after` header in seconds and statusCode 503', function (done) {
      var retryAfterDelay = 0.5; // 500ms
      var retryAfterDelayMs = retryAfterDelay * 1000;
      var restartDate = (Date.now() + retryAfterDelayMs);

      var path = '/retry-later';
      var errorMessage = 'Service is NOT available';
      var message = 'Hello Dave I\'m back';

      var server = http2.createServer(serverOptions, function (request, response) {
          var requestDate = Date.now();
          expect(request.url).to.equal(path);

          // DEBUG:
          //console.log('request', request.url, requestDate, restartDate, requestDate < restartDate);

          if (requestDate < restartDate) {
            response.setHeader('retry-after', retryAfterDelay);
            response.writeHead(503);
            response.write(errorMessage);
            response.end(); 
          } else {
            response.writeHead(200);
            response.write(message);
            response.end(); 
          }
      });

      server.listen(1244, function () {
          var options = url.parse('https://localhost:1244' + path);
          options.key = agentOptions.key;
          options.ca = agentOptions.ca;
          options.rejectUnauthorized = true;

          http2.globalAgent = new http2.Agent({log: util.clientLog});
          http2.get(options, function (response) {

              // DEBUG:
              //console.log('response', response.statusCode);
              
              expect(response.statusCode).to.equal(200);
              
              response.on('data', function (data) {
                  // TODO
                  expect(data.toString()).to.equal(message);
              });

              response.on('end',function(){
                // WHY finished undefined ?
                //expect(response.finished).to.equal(true);
                server.close();
                done();
              });
          });
      });
    }).timeout(1000);

    it('does a request and gets a response statusCode 200 with `retry-after` header using date and statusCode 503', function (done) {
      var retryAfterDelay = 5;
      var retryAfterDelayMs = retryAfterDelay * 1000;
      var restartDate = (Date.now() + retryAfterDelayMs);

      var path = '/retry-later';
      var errorMessage = 'Service is NOT available';
      var message = 'Hello Dave I\'m back';

      var server = http2.createServer(serverOptions, function (request, response) {
        var requestDate = Date.now();
          expect(request.url).to.equal(path);

          // DEBUG:
          //console.log('request', request.url, requestDate, restartDate, restartDate - requestDate, requestDate < restartDate);

          if (requestDate < restartDate) {
            response.setHeader('retry-after', new Date(restartDate));
            response.writeHead(503);
            response.write(errorMessage);
            response.end(); 
          } else {
            response.writeHead(200);
            response.write(message);
            response.end(); 
          }
      });

      server.listen(1244, function () {
          var options = url.parse('https://localhost:1244' + path);
          options.key = agentOptions.key;
          options.ca = agentOptions.ca;
          options.rejectUnauthorized = true;

          http2.globalAgent = new http2.Agent({log: util.clientLog});
          http2.get(options, function (response) {

              // DEBUG:
              //console.log('response', response.statusCode);
              
              expect(response.statusCode).to.equal(200);
              
              response.on('data', function (data) {
                  // TODO
                  expect(data.toString()).to.equal(message);
              });

              response.on('end',function(){
                // WHY finished undefined ?
                //expect(response.finished).to.equal(true);
                server.close();
                done();
              });
          });
      });
    }).timeout(6000);

    it('does a request and gets a response statusCode 200 with `retry-after` header using date and statusCode 503 using POST', function (done) {
      var retryAfterDelay = 5;
      var retryAfterDelayMs = retryAfterDelay * 1000;
      var restartDate = (Date.now() + retryAfterDelayMs);

      var path = '/retry-later';
      var errorMessage = 'Service is NOT available';
      var message = 'Hello Dave I\'m back';

      var server = http2.createServer(serverOptions, function (request, response) {
        var requestDate = Date.now();
          expect(request.url).to.equal(path);
          expect(request.method).to.equal('POST');
          expect(request.headers["content-type"]).to.equal("text/plain");

          var body = [];
          request.on('data', function(chunk) {
            body.push(chunk);
          }).on('end', function() {
            // at this point, `body` has the entire request body stored in it as a string
            expect(Buffer.concat(body).toString()).to.equal(message);
          });

          // DEBUG:
          //console.log('request', request.url, requestDate, restartDate, restartDate - requestDate, requestDate < restartDate);

          if (requestDate < restartDate) {
            response.setHeader('retry-after', new Date(restartDate));
            response.writeHead(503);
            response.write(errorMessage);
            response.end(); 
          } else {
            response.writeHead(200);
            response.write(message);
            response.end(); 
          }
      });

      server.listen(1244, function () {
          var options = url.parse('https://localhost:1244' + path);
          options.key = agentOptions.key;
          options.ca = agentOptions.ca;
          options.method = 'POST';
          options.rejectUnauthorized = true;
          options.headers = {
            "Content-Type": "text/plain"
          };

          http2.globalAgent = new http2.Agent({log: util.clientLog});
          http2.post(options, message, function (response) {

              // DEBUG:
              //console.log('response', response.statusCode);
              expect(response.statusCode).to.equal(200);
              
              response.on('data', function (data) {
                  // TODO
                  expect(data.toString()).to.equal(message);
              });

              response.on('end',function(){
                // WHY finished undefined ?
                //expect(response.finished).to.equal(true);
                server.close();
                done();
              });
          });
      });
    }).timeout(6000);

    it('does a request and gets a response statusCode 200 with `retry-after` header and statusCode 503 with gzip encoding', function (done) {
      var retryAfterDelay = 5;
      //retryAfterDelay = 0;
      var retryAfterDelayMs = retryAfterDelay * 1000;
      var restartDate = (Date.now() + retryAfterDelayMs);

      var path = '/retry-later';
      var errorMessage = 'Service is NOT available';
      var message = 'Hello Dave I\'m back';

      var compressedErrorMessage = pako.gzip(errorMessage);
      compressedErrorMessage = Buffer.from(compressedErrorMessage.buffer);

      var compressedMessage = pako.gzip(message);
      compressedMessage = Buffer.from(compressedMessage.buffer);

      var server = http2.createServer(serverOptions, function (request, response) {
        var requestDate = Date.now();
          expect(request.url).to.equal(path);
          response.setHeader('content-encoding', 'gzip');

          // DEBUG:
          //console.log('request', request.url, requestDate, restartDate, requestDate < restartDate);
          var responseMessage, compressedResponseMessage;
          if (requestDate < restartDate) {
            response.setHeader('retry-after', retryAfterDelay);
            response.writeHead(503);
            responseMessage = errorMessage;
            compressedResponseMessage = compressedErrorMessage;
          } else {
            response.writeHead(200);
            responseMessage = message;
            compressedResponseMessage = compressedMessage;
          }

          var chunk1 = Buffer.from(responseMessage, 0, 15);
          response.write(chunk1);
          response.write(Buffer.from(compressedResponseMessage, 0, 0));
          var chunk2 = Buffer.from(compressedResponseMessage, 15);
          response.write(chunk2);
          response.end();
      });

      server.listen(1244, function () {
          var options = url.parse('https://localhost:1244' + path);
          options.key = agentOptions.key;
          options.ca = agentOptions.ca;
          options.rejectUnauthorized = true;

          http2.globalAgent = new http2.Agent({log: util.clientLog});
          http2.get(options, function (response) {

              expect(response.statusCode).to.equal(200);
              
              response.on('data', function (data) {
                  expect(data.toString()).to.equal(message);
              });

              response.on('end',function(){
                // WHY finished undefined ?
                //expect(response.finished).to.equal(true);
                server.close();
                done();
              });
          });
      });
    }).timeout(6000);
  });

  describe('Agent', function() {
    describe('property `maxSockets`', function() {
      it('should be a proxy for the backing HTTPS agent\'s `maxSockets` property', function() {
        var agent = new http2.Agent({ log: util.clientLog });
        var backingAgent = agent._httpsAgent;
        var newMaxSockets = backingAgent.maxSockets + 1;
        agent.maxSockets = newMaxSockets;
        expect(agent.maxSockets).to.be.equal(newMaxSockets);
        expect(backingAgent.maxSockets).to.be.equal(newMaxSockets);
      });
    });

    describe('method `request(options, [callback])`', function() {
      it('should use a new agent for request-specific TLS settings', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1234, function() {
          var options = url.parse('https://localhost:1234' + path);
          options.key = agentOptions.key;
          options.ca = agentOptions.ca;
          options.rejectUnauthorized = true;

          http2.globalAgent = new http2.Agent({ log: util.clientLog });
          http2.get(options, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              server.close();
              done();
            });
          });
        });
      });
      it('should throw when trying to use with \'http\' scheme', function() {
        expect(function() {
          var agent = new http2.Agent({ log: util.clientLog });
          agent.request({ protocol: 'http:' });
        }).to.throw(Error);
      });
    });
  });
  describe('OutgoingRequest', function() {
    function testFallbackProxyMethod(name, originalArguments, done) {
      var request = new http2.OutgoingRequest();

      // When in HTTP/2 mode, this call should be ignored
      request.stream = { reset: util.noop };
      request[name].apply(request, originalArguments);
      delete request.stream;

      // When in fallback mode, this call should be forwarded
      request[name].apply(request, originalArguments);
      var mockFallbackRequest = { on: util.noop };
      mockFallbackRequest[name] = function() {
        expect(Array.prototype.slice.call(arguments)).to.deep.equal(originalArguments);
        done();
      };
      request._fallback(mockFallbackRequest);
    }
    describe('method `setNoDelay(noDelay)`', function() {
      it('should act as a proxy for the backing HTTPS agent\'s `setNoDelay` method', function(done) {
        testFallbackProxyMethod('setNoDelay', [true], done);
      });
    });
    describe('method `setSocketKeepAlive(enable, initialDelay)`', function() {
      it('should act as a proxy for the backing HTTPS agent\'s `setSocketKeepAlive` method', function(done) {
        testFallbackProxyMethod('setSocketKeepAlive', [true, util.random(10, 100)], done);
      });
    });
    describe('method `setTimeout(timeout, [callback])`', function() {
      it('should act as a proxy for the backing HTTPS agent\'s `setTimeout` method', function(done) {
        testFallbackProxyMethod('setTimeout', [util.random(10, 100), util.noop], done);
      });
    });
    describe('method `abort()`', function() {
      it('should act as a proxy for the backing HTTPS agent\'s `abort` method', function(done) {
        testFallbackProxyMethod('abort', [], done);
      });
    });
  });
  describe('OutgoingResponse', function() {
    it('should throw error when writeHead is called multiple times on it', function() {
      var called = false;
      var stream = { _log: util.log, headers: function () {
        if (called) {
          throw new Error('Should not send headers twice');
        } else {
          called = true;
        }
      }, once: util.noop };
      var response = new http2.OutgoingResponse(stream);

      response.writeHead(200);
      response.writeHead(404);
    });
    it('field finished should be Boolean', function(){
      var stream = { _log: util.log, headers: function () {}, once: util.noop };
      var response = new http2.OutgoingResponse(stream);
      expect(response.finished).to.be.a('Boolean');
    });
    it('field finished should initially be false and then go to true when response completes',function(done){
      var res;
      var server = http2.createServer(serverOptions, function(request, response) {
        res = response;
        expect(res.finished).to.equal(false);
        response.end('HiThere');
      });
      server.listen(1236, function() {
        http2.get('https://localhost:1236/finished-test', function(response) {
          response.on('data', function(data){
            var sink = data; //
          });
          response.on('end',function(){
            expect(res.finished).to.equal(true);
            server.close();
            done();
          });
        });
      });
    });
  });
  describe('test scenario', function() {
    describe('simple request', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1234, function() {
          http2.get('https://localhost:1234' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              server.close();
              done();
            });
          });
        });
      });
    });
    describe('2 simple request in parallel', function() {
      it('should work as expected', function(originalDone) {
        var path = '/x';
        var message = 'Hello world';
        var done = util.callNTimes(2, function() {
          server.close();
          originalDone();
        });

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1234, function() {
          http2.get('https://localhost:1234' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
          http2.get('https://localhost:1234' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
        });
      });
    });
    describe('2 simple request in parallel shoudl fail if SETTINGS_MAX_CONCURRENT_STREAMS=1', function() {
      it('should work as expected', function(originalDone) {
        var path = '/x';
        var message = 'Hello world';
        var done = util.callNTimes(2, function() {
          server.close();
          originalDone();
        });

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        http2.globalAgent = new http2.Agent(Object.assign({
          log: util.clientLog,
          settings: {
            SETTINGS_MAX_CONCURRENT_STREAMS: 1
          }
        }, agentOptions));

        var start = Date.now();

        server.listen(1234, function() {
          http2.get('https://localhost:1234' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
          http2.get('https://localhost:1234' + path, function(response) {
            // TODO assert and expect queueing on globalAgent->Endpoint->Connection
            response.on('data', function(data) {
              console.log(Date.now() - start);
              expect(data.toString()).to.equal(message);
              done();
            });
          });
        });
      });
    });
    describe('100 simple request in a series', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        var n = 100;
        server.listen(1242, function() {
          doRequest();
          function doRequest() {
            http2.get('https://localhost:1242' + path, function(response) {
              response.on('data', function(data) {
                expect(data.toString()).to.equal(message);
                if (n) {
                  n -= 1;
                  doRequest();
                } else {
                  server.close();
                  done();
                }
              });
            });
          }
        });
      });
    });
    describe('request with payload', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          request.once('data', function(data) {
            expect(data.toString()).to.equal(message);
            response.end();
          });
        });

        server.listen(1240, function() {
          var request = http2.request({
            host: 'localhost',
            port: 1240,
            path: path
          });
          request.write(message);
          request.end();
          request.on('response', function() {
            server.close();
            done();
          });
        });
      });
    });
    describe('request with custom status code and headers', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';
        var headerName = 'name';
        var headerValue = 'value';

        var server = http2.createServer(serverOptions, function(request, response) {
          // Request URL and headers
          expect(request.url).to.equal(path);
          expect(request.headers[headerName]).to.equal(headerValue);

          // A header to be overwritten later
          response.setHeader(headerName, 'to be overwritten');
          expect(response.getHeader(headerName)).to.equal('to be overwritten');

          // A header to be deleted
          response.setHeader('nonexistent', 'x');
          response.removeHeader('nonexistent');
          expect(response.getHeader('nonexistent')).to.equal(undefined);

          // A set-cookie header which should always be an array
          response.setHeader('set-cookie', 'foo');

          // Don't send date
          response.sendDate = false;

          // Specifying more headers, the status code and a reason phrase with `writeHead`
          var moreHeaders = {};
          moreHeaders[headerName] = headerValue;
          response.writeHead(600, 'to be discarded', moreHeaders);
          expect(response.getHeader(headerName)).to.equal(headerValue);

          // Empty response body
          response.end(message);
        });

        server.listen(1239, function() {
          var headers = {};
          headers[headerName] = headerValue;
          var request = http2.request({
            host: 'localhost',
            port: 1239,
            path: path,
            headers: headers
          });
          request.end();
          request.on('response', function(response) {
            expect(response.headers[headerName]).to.equal(headerValue);
            expect(response.headers['nonexistent']).to.equal(undefined);
            expect(response.headers['set-cookie']).to.an.instanceof(Array);
            expect(response.headers['set-cookie']).to.deep.equal(['foo']);
            expect(response.headers['date']).to.equal(undefined);
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              server.close();
              done();
            });
          });
        });
      });
    });
    describe('request over generic plain transport (example WebSocket)', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';
        var portnum = 1239;

        var server = http2.raw.createServer({
          log: util.serverLog,
          transport: function(options, start){
            var httpServer = http.createServer();
            options.server = httpServer;
            var res = websocket.createServer(options, start);
            res.listen = function(options, cb){
              httpServer.listen(options, cb);
            };
            res.close = function (cb) {
              httpServer.close(cb);
            };
            return res;
          }
        }, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });
        server.listen(portnum, function() {
          var request = http2.raw.request({
            plain: true,
            host: 'localhost',
            port: portnum,
            path: path,
            transport: websocket('ws://localhost:' + portnum)
          }, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              server.close();
              done();
            });
          });
          request.end();
        });
      });
    });

    describe('get over plain generic transport (example WebSocket)', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var portnum = 1239;
        var message = 'Hello world';

        var server = http2.raw.createServer({
          log: util.serverLog,
          transport: function(options, start){
            var httpServer = http.createServer();
            options.server = httpServer;
            var res = websocket.createServer(options, start);
            res.listen = function(options, cb){
              httpServer.listen(options, cb);
            };
            res.close = function (cb) {
              httpServer.close(cb);
            };
            return res;
          }
        }, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(portnum, function() {
          var request = http2.raw.get({
            path: path,
            transport: websocket('ws://localhost:' + portnum)
          }, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              server.close();
              done();
            });
          });
          request.end();
        });
      });
    });
    describe('get over plain generic transport (example WebSocket) 2', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.raw.createServer({
          log: util.serverLog,
          transport: function(options, start){
            var httpServer = http.createServer();
            options.server = httpServer;
            var res = websocket.createServer(options, start);
            res.listen = function(options, cb){
              httpServer.listen(options, cb);
            };
            res.close = function (cb) {
              httpServer.close(cb);
            };
            return res;
          }
        }, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1239, function() {
          var request = http2.raw.get({path: path, transport: function() {
              return websocket('ws://localhost:' + 1239);
          }}, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              server.close();
              done();
            });
          });
          request.end();
        });
      });
    });
    describe('request over plain TCP', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.raw.createServer({
          log: util.serverLog
        }, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1237, function() {
          var request = http2.raw.request({
            plain: true,
            host: 'localhost',
            port: 1237,
            path: path
          }, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              server.close();
              done();
            });
          });
          request.end();
        });
      });
    });
    describe('get over plain TCP', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.raw.createServer({
          log: util.serverLog
        }, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1237, function() {
          var request = http2.raw.get('http://localhost:1237/x', function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              server.close();
              done();
            });
          });
          request.end();
        });
      });
    });
    describe('request to an HTTPS/1 server', function() {
      it('should fall back to HTTPS/1 successfully', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = https.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(5678, function() {
          http2.get('https://localhost:5678' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
        });
      });
    });
    describe('2 parallel request to an HTTPS/1 server', function() {
      it('should fall back to HTTPS/1 successfully', function(originalDone) {
        var path = '/x';
        var message = 'Hello world';
        var done = util.callNTimes(2, function() {
          server.close();
          originalDone();
        });

        var server = https.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(6789, function() {
          http2.get('https://localhost:6789' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
          http2.get('https://localhost:6789' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
        });
      });
    });
    describe('HTTPS/1 request to a HTTP/2 server', function() {
      it('should fall back to HTTPS/1 successfully', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1236, function() {
          var options = url.parse('https://localhost:1236' + path);
          options.agent = new https.Agent(agentOptions);
          https.get(options, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
        });
      });
    });
    describe('two parallel request', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1237, function() {
          done = util.callNTimes(2, done);
          // 1. request
          http2.get('https://localhost:1237' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
          // 2. request
          http2.get('https://localhost:1237' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
          });
        });
      });
    });
    describe('two subsequent request', function() {
      it('should use the same HTTP/2 connection', function(done) {
        var path = '/x';
        var message = 'Hello world';

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          response.end(message);
        });

        server.listen(1238, function() {
          // 1. request
          http2.get('https://localhost:1238' + path, function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);

              // 2. request
              http2.get('https://localhost:1238' + path, function(response) {
                response.on('data', function(data) {
                  expect(data.toString()).to.equal(message);
                  done();
                });
              });
            });
          });
        });
      });
    });
    describe('https server node module specification conformance', function() {
      it('should provide API for remote HTTP 1.1 client address', function(done) {
        var remoteAddress = null;
        var remotePort = null;

        var server = http2.createServer(serverOptions, function(request, response) {
          // HTTPS 1.1 client with Node 0.10 server
          if (!request.remoteAddress) {
            if (request.socket.socket) {
              remoteAddress = request.socket.socket.remoteAddress;
              remotePort = request.socket.socket.remotePort;
            } else {
              remoteAddress = request.socket.remoteAddress;
              remotePort = request.socket.remotePort;
            }
          } else {
            // HTTPS 1.1/2.0 client with Node 0.12 server
            remoteAddress = request.remoteAddress;
            remotePort = request.remotePort;
          }
          response.write('Pong');
          response.end();
        });

        server.listen(1259, 'localhost', function() {
          var request = https.request({
            host: 'localhost',
            port: 1259,
            path: '/',
            method: 'POST',
            ca: serverOptions.cert
          });
          request.write('Ping');
          request.end();
          request.on('response', function(response) {
            response.on('data', function(data) {
              var localAddress = response.socket.address();
              expect(remoteAddress).to.equal(localAddress.address);
              expect(remotePort).to.equal(localAddress.port);
              server.close();
              done();
            });
          });
        });
      });
      it('should provide API for remote HTTP 2.0 client address', function(done) {
        var remoteAddress = null;
        var remotePort = null;
        var localAddress = null;

        var server = http2.createServer(serverOptions, function(request, response) {
          remoteAddress = request.remoteAddress;
          remotePort = request.remotePort;
          response.write('Pong');
          response.end();
        });

        server.listen(1258, 'localhost', function() {
          var request = http2.request({
            host: 'localhost',
            port: 1258,
            path: '/'
          });
          request.write('Ping');
          globalAgent.on('false:localhost:1258', function(endpoint) {
            localAddress = endpoint.socket.address();
          });
          request.end();
          request.on('response', function(response) {
            response.on('data', function(data) {
              expect(remoteAddress).to.equal(localAddress.address);
              expect(remotePort).to.equal(localAddress.port);
              server.close();
              done();
            });
          });
        });
      });
      it('should expose net.Socket as .socket and .connection', function(done) {
        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.socket).to.equal(request.connection);
          expect(request.socket).to.be.instanceof(net.Socket);
          response.write('Pong');
          response.end();
          done();
        });

        server.listen(1248, 'localhost', function() {
          var request = https.request({
            host: 'localhost',
            port: 1248,
            path: '/',
            ca: serverOptions.cert
          });
          request.write('Ping');
          request.end();
        });
      });
    });
    describe('request and response with trailers', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';
        var requestTrailers = { 'content-md5': 'x' };
        var responseTrailers = { 'content-md5': 'y' };

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          request.on('data', util.noop);
          request.once('end', function() {
            expect(request.trailers).to.deep.equal(requestTrailers);
            response.write(message);
            response.addTrailers(responseTrailers);
            response.end();
          });
        });

        server.listen(1241, function() {
          var request = http2.request('https://localhost:1241' + path);
          request.addTrailers(requestTrailers);
          request.end();
          request.on('response', function(response) {
            response.on('data', util.noop);
            response.once('end', function() {
              expect(response.trailers).to.deep.equal(responseTrailers);
              done();
            });
          });
        });
      });
    });
    describe('Handle socket error', function () {
      it('HTTPS on Connection Refused error', function (done) {
        var path = '/x';
        var request = http2.request('https://127.0.0.1:6666' + path);

        request.on('error', function (err) {
          expect(err.errno).to.equal('ECONNREFUSED');
          done();
        });

        request.on('response', function (response) {
          //server._server._handle.destroy();

          response.on('data', util.noop);

          response.once('end', function () {
            done(new Error('Request should have failed'));
          });
        });

        request.end();

      });
      it('HTTP on Connection Refused error', function (done) {
        var path = '/x';

        var request = http2.raw.request('http://127.0.0.1:6666' + path);

        request.on('error', function (err) {
          expect(err.errno).to.equal('ECONNREFUSED');
          done();
        });

        request.on('response', function (response) {
          //server._server._handle.destroy();

          response.on('data', util.noop);

          response.once('end', function () {
            done(new Error('Request should have failed'));
          });
        });

        request.end();
      });
    });
    describe('server push', function() {
      it('should work as expected', function(done) {
        var path = '/x';
        var message = 'Hello world';
        var pushedPath = '/y';
        var pushedMessage = 'Hello world 2';

        var server = http2.createServer(serverOptions, function(request, response) {
          expect(request.url).to.equal(path);
          var push1 = response.push('/y');
          push1.end(pushedMessage);
          var push2 = response.push({ path: '/y', protocol: 'https:' });
          push2.end(pushedMessage);
          response.end(message);
        });

        server.listen(1235, function() {
          var request = http2.get('https://localhost:1235' + path);
          done = util.callNTimes(5, done);

          request.on('response', function(response) {
            response.on('data', function(data) {
              expect(data.toString()).to.equal(message);
              done();
            });
            response.on('end', done);
          });

          request.on('push', function(promise) {
            expect(promise.url).to.be.equal(pushedPath);
            promise.on('response', function(pushStream) {
              pushStream.on('data', function(data) {
                expect(data.toString()).to.equal(pushedMessage);
                done();
              });
              pushStream.on('end', done);
            });
          });
        });
      });
    });
  });
});
