/* main.js */

$(document).ready(function(){
    console.log(document.cookie);
    var socket = io();
    io.on('connection', function(socket){
        console.log("kek");
    });
});
