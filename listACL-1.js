/*
#
# Copyright (c) 2016 Wojciechowski Piotr
# https://facebook.com/Piotr.Wojciechowski.CCIE
# https://ccieplayground.wordpress.com/
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
*/

var https = require('https');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

var data = {};
// Hardcoded firewall IP
var server = "172.16.1.51";

// Default credentials
var username = "cisco";
var password = "cisco";

// Hardcoded API path
var api_path = "/api/access/in/lxc-sshd-5/rules/"; // param

// Hardcoded connection options
var options = {
    host: server,
    path: api_path,
    method: "GET",
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + new Buffer(username + ':' + password).toString('base64')
    }
};

// Create local HTTP server
var HTTPServer = require('http');

// Create Server (listen port defined at the end)
HTTPServer.createServer(function(request, response) {
    // Send HTTPS request for REST API method to ASA
    var req = https.request(options, function(res) {
        // Some local console debugging about response from ASA
        console.log("statusCode: ", res.statusCode);
        console.log("headers: ", res.headers);
        console.log("----\n\n");

        // This array will be used to store JSON response
        var JSON_ExtendedACE = [];

        // In asynchronous mode push method is used to update result string
        res.on('data', function(d) {
            // When any chunk of data is received it will be added
            // To JSON_ExtendedACE array
            JSON_ExtendedACE.push(d);
        });

        // This will execute when all data is received
        res.on('end', function() {
            // Received array is oparsed into JSON structure
            var JSONStructure = JSON.parse(JSON_ExtendedACE);
            // HTML headers wrote to our HTTP server output
            response.write('<html><body>');
            // Response recorded in JSON consist of multiple items so we
            // process each item separately
            JSONStructure.items.forEach(function(item) {
                // Each item can have different structure so we process it
                // by displaying different values
                if (item.sourceAddress.objectId) {
                    // If item have "objectId" field we will display it
                    // It's for entries like object or object-group
                    console.log(item.sourceAddress.objectId);
                    response.write(item.sourceAddress.objectId + '<br>');
                } else if (item.sourceAddress.value) {
                    // If item is just IP address we will display it
                    console.log(item.sourceAddress.value);
                    response.write(item.sourceAddress.value + '<br>');
                }
            });
            // Closing HTML headers
            response.write('</body></html>');
            // Closing HTTP pipe to client
            response.end();
        });
    });
    // Closing connection to REST API
    req.end();

    // Error handler if firewall REST API is not responding
    req.on('error', function(e) {
        console.error(e);
    });
}).listen(8080); // Definition of listening port
