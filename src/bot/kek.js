var Steam = require('steam');
var SteamUser = require('steam-user');
var SteamTotp = require('steam-totp');
var Winston = require('winston');
var TradeOfferManager = require('steam-tradeoffer-manager');
var config = require('./config.js');
var fs = require('fs');
var SteamCommunity = require('steamcommunity');
var client = new SteamUser();
var community = new SteamCommunity(steamClient);
var steamClient = new Steam.SteamClient();


var appid = {
  CSGO: 730
}
var contextid = {
  CSGO: 2
}
var logger = new (Winston.Logger)({
        transports: [
            new (Winston.transports.Console)({
                colorize: true,
                level: 'debug'
            }),
            new (Winston.transports.File)({
                level: 'info',
                timestamp: true,
                filename: 'cratedump.log',
                json: false
            })
        ]
});

var offers = new TradeOfferManager({
    steam:        client,
    domain:       config.domain,
    language:     "en",
    pollInterval: 10000
});

fs.readFile('polldata.json', function (err, data) {
    if (err) {
        logger.warn('Error reading polldata.json. If this is the first run, this is expected behavior: '+err);
    } else {
        logger.debug("Found previous trade offer poll data.  Importing it to keep things running smoothly.");
        offers.pollData = JSON.parse(data);
    }
});

client.setOption("promptSteamGuardCode", false);

client.logOn({
  accountName: config.username,
  password: config.password,
});



client.on('error', function(e){
  logger.error(e);
  process.exit(1);
});

client.on('webSession',function (steamID, cookies){
  logger.debug("Got web session");
  offers.setCookies(cookies, function(err){
    if(err){
      logger.error('Unable to set trade offer cookies: ' +err);
      process.exit(1);
    }
    logger.debug("offer cookies set. API Key: "+offers.apiKey);
    community.setCookies(cookies);
    SteamTotp.steamID = steamID;
    community.startConfirmationChecker(2500, config.identitySecret);
    doStuff();
  });
});

client.on('loggedOn', function(details){
  client.setPersona(SteamUser.Steam.EPersonaState.Online);
  logger.info("Logged in")
});

client.on("steamGuard", function(domain, callback, lastCodeWrong){
  var shared_secret = config.sharedsecret;
  callback(SteamTotp.generateAuthCode(shared_secret));
});


function doStuff(){
offers.on('newOffer', function (offer) {
    logger.info("New offer #"+ offer.id +" from "+ offer.partner.getSteam3RenderedID());
    if (offer.partner.getSteamID64() === config.admin) {
      offer.accept(function (err) {
        if(err){
          logger.error("Unable to accept offer " + offer.id);
        } else{
          logger.info("accepted offer")
        }
      });
    } else{
      offer.decline(function(err){
        if(err) {
          logger.error("cant decline trade " + offer.id + " cuz " + err.message);
        }
        else{
          logger.debug("Offer declined");
        }
      });
    }
});

offers.on('sentOfferChanged', function (offer, oldState) {
  if(offer.state == TradeOfferManager.ETradeOfferState.Accepted) {
    logger.info("offer " + offer.id + " accepted");
  }
});

offers.on('pollFailure',function(err){
  logger.error("Error polling: " + err);
})

if(config.statuskek == '1')
{
  offers.loadUserInventory(config.tradeID, appid.CSGO, contextid.CSGO, true, function (err, inventory){
       if (err) {
           logger.error(err);
       } else {
         var pool = inventory.filter( function(item){
           for(var i = 0; i <config.itemList.length; i++){
              var kek = config.itemList[i].split('.')
             if(item.name.includes(kek[0])){
               if(config.itemList[i].includes("Battle-Scarred") || config.itemList[i].includes("Well-Worn") || config.itemList[i].includes("Field-Tested") || config.itemList[i].includes("Minimal Wear") || config.itemList[i].includes("Factory New")){
                 var condition = kek[1].replace(/[(|)]/g, "")
                 JSON.stringify(item.tags[5]);
                 if(item.tags[5].name.includes(condition)){
                   logger.info("Found " + item.name + " (" + item.tags[5].name + ")")
                   config.itemList.splice(i,1);
                   return true;
                 }
               }
               if(config.itemList[i].includes("Case") || config.itemList[i].includes("Sticker"))
               {
                 logger.info("adding " + item.name)
                 config.itemList.splice(i,1)
                 return true;
               }
             }
           }
           return false
           });




           var trade = offers.createOffer(config.tradeID);
           logger.info('Starting Trade with ' + config.tradeID);
           logger.info('Added ' + pool.length + ' items');
           trade.addTheirItems(pool);
           trade.setMessage("sent by bot");
           trade.send(function (err, status){
               if (err) {
                   logger.error(err);
               } else if (status == 'pending'){
                   logger.warn('Trade pending...');
               } else {
                   logger.info('Trade offer sent successfully');
               }
             });


       }
   })
 }
 }
