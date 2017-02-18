var expect = require('chai').expect;
var http2 = require('../lib/http');
var websocket = require('websocket-stream');

describe('http2-cache', function () {

    // TODO consider doing browser testing
    // if (browserConfig) {
    //     browserConfig.origin('http://localhost:8080').addResource("http://chaijs.com/chai.js");
    // }
console.log("start");
    it('http2.get.over.ws', function (done) {
        // var request = http2.raw.request({
        //     plain: true,
        //     host: 'localhost',
        //     port: 8080,
        //     transport: function(){
        //         console.log("DPW got called here");
        //         return websocket('ws://localhost:8080/echo');
        //     }
        // }, function(response) {
        //     console.log("Response with: " + response.statusCode);
        //     response.on('data', function(data) {
        //         console.log(" " + data);
        //         done();
        //     });
        // });
        // request.end();
        console.log("waiting for ever");
    });

});

