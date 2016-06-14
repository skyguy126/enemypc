var socket;

$(function () {
    socket = io.connect('wss://24.4.237.252/sock');
    socket.on('connect', function () {
        console.log('connected');
        socket.emit('sock_auth', { "cookie": document.cookie });
    });
});
