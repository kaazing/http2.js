var request = http2.raw.request({
            plain: true,
            host: 'localhost',
            port: 8080,
            transport: function(){
                console.log("DPW got called here");
                return websocket('ws://localhost:8080/echo');
            }
        }, function(response) {
            console.log("Response with: " + response.statusCode);
            response.on('data', function(data) {
                console.log(" " + data);
            });
        });
        request.end();
});


