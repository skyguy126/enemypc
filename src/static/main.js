/* main.js */

$(document).ready(function(){
    console.log("Ready!");

    //$("#1").click(function(){
    //    $(this).prop("disabled", true);
    //    $.ajax({
    //        type : "POST",
    //        async : true,
    //        url : "search",
    //        data : {
    //            id : $("#2").val()
    //        },
    //        statusCode : {
    //            200 : function(data) {
    //                console.log(data);
    //                $("#1").prop("disabled", false);
    //            }
    //        }
    //    });
    //});

    var socket = io.connect('/sock');
    socket.on('connection', function () {
        socket.on('data', function (data) {
            console.log(data);
        });
    });
});
