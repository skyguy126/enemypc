var SteamUser = require('steam-user');
var Winston = require('winston');
var TradeOfferManager = require('steam-tradeoffer-manager');
var config = require('./config.js');
var fs = require('fs');
var itemList = ["SCAR-20 | Contractor.(Field-Tested)", "P250 | Sand Dune.(Battle-Scarred)" , "G3SG1 | Desert Storm.(Well-Worn)"];
var statuskek = 1;
var steamID = '76561198021306496';

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

var client = new SteamUser();
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

client.logOn({
  accountName: config.username,
  password: config.password
});

client.on('loggedOn', function(details){
  logger.info("Logged in")
});

client.on('error', function(e){
  logger.error(e);
  process.exit(1);
});

client.on('webSession',function (sessionID, cookies){
  logger.debug("Got web session");
  client.setPersona(SteamUser.Steam.EPersonaState.Online);
  offers.setCookies(cookies, function(err){
    if(err){
      logger.error('Unable to set trade offer cookies: ' +err);
      process.exit(1);
    }
    logger.debug("offer cookies set. API Key: "+offers.apiKey);
    doStuff();
  });
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
          logger.error("cant decline trade" + offer.id + "cuz" + err.message);
        }
        else{
          logger.debug("Offer declined");
        }
      });
    }
});

offers.on('sentOfferChanged', function (offer, oldState) {
  if(offer.state == TradeOfferManager.ETradeOfferState.Accepted) {
    logger.info("offer" + offer.id + "accepted");
  }
});

offers.on('pollFailure',function(err){
  logger.error("Error polling:" + err);
})

if(statuskek == '1')
{
  offers.loadUserInventory(steamID, appid.CSGO, contextid.CSGO, true, function (err, inventory){
       if (err) {
           logger.error(err);
       } else {
         var pool = inventory.filter( function(item){
           for(var i = 0; i <itemList.length; i++){
              var kek = itemList[i].split('.')
             if(item.name.includes(kek[0])){
               logger.info("Item found")
               if(itemList[i].includes("Battle-Scarred") || itemList[i].includes("Well-Worn") || itemList[i].includes("Field-Tested") || itemList[i].includes("Minimal Wear") || itemList[i].includes("Factory New")){
                 var condition = kek[1].replace(/[(|)]/g, "")
                 logger.info('test ' + condition)
                 JSON.stringify(item.tags[5]);
                 logger.info("" + item.name);
                 logger.info("" + item.tags.length);
                 logger.info("" + item.tags[5])
                 if(item.tags.indexOf(condition) > -1){
                   return true;
                   itemList.splice(i,1);
                   logger.info("adding" + itemList[1])
                 }
               }
               if(itemList[i].includes("Case") || itemList[i].includes("Sticker"))
               {
                 return true;
                 itemList.splice(i,1);
               }
             }
           }
           return false
           });




           var trade = offers.createOffer(steamID);
           logger.info('Starting Trade with' + steamID);
           logger.debug('Adding items');
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
