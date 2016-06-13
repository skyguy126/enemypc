var SteamUser = require('steam-user');
var Winston = require('winston');
var TradeOfferManager = require('steam-tradeoffer-manager');
var config = require('./config.js');
var fs = require('fs');

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
  });
});

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

if(status == 1)
{
  offers.loadUserInventory(steamID,appid.CSGO,contextid.CSGO,true,function(err, inventory){
    if(err)
    {
      logger.error(err);
    }else{
      var pool = inventory.filter(function(item){
        return item.tags.some(function(element, index, array){
          itemList.forEach(function(name){
            return element.internal_name == name;
          })
        });
      });
  var trade = offers.createOffer(steamID);
  trade.addTheirItems(pool);
  trade.send('sent by bot', function(err, status){
    if(err){
      logger.error(err);
    } else if (status == 'pending'){
      logger.info('pending...')
    } else{
      logger.info('successfully sent')
      }
    });
    }
  });
}
