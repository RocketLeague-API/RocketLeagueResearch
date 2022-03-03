const request = require("request");
const WebSocket = require('websocket');
const Crypto = require('crypto-js');
const SteamClient = require('steam-user')

const RLAppId = 252950; //https://steamdb.info/app/252950/
const RLKey = "c338bd36fb8c42b1a431d30add939fc7";
const RLUserAgent = 'RL Win/211123.48895.355454 gzip';
const RLLanguage = 'INT';
const RLFeatureSet = 'PrimeUpdate36_2';
const RLBuildId = '-960700785';
const RLEnvironment = 'Prod';

const { DisplayName, Username, Password } = require("./config.json");
const steamClient = new SteamClient();

steamClient.logOn({
    "accountName": Username,
    "password": Password
});

function createSignature(payload) {
    let signature = Crypto.HmacSHA256(`-${payload}`, RLKey).toString();
    return Buffer.from(signature, 'hex').toString('base64');
}

function getAuthentication(access_token, account_id, display_name, callback) {
    let authenticationPayload = JSON.stringify([
        {
            Service: 'Auth/AuthPlayer',
            Version: 2,
            ID: 1,
            Params: {
                Platform: 'Steam',
                PlayerName: display_name,
                PlayerID: account_id,
                Language: RLLanguage,
                AuthTicket: access_token,
                BuildRegion: '',
                FeatureSet: RLFeatureSet,
                bSkipAuth: false
            }
        }
    ]); 

    request.post({
        url: "https://api.rlpp.psynet.gg/Services",
        headers: {
            'Content-Type': "application/x-www-form-urlencoded",
            'User-Agent': RLUserAgent,
            'Cache-Control': 'no-cache',
            'PsyBuildID': RLBuildId,
            'PsyEnvironment': RLEnvironment,
            'PsyRequestID': 'PsyNetMessage_X_0',
            'PsySig': createSignature(authenticationPayload)
        },
        body: authenticationPayload,
    }, (error, response, body) => {
        if(error) {
            console.log("[Psyonix Error] Error at authenticating...")
            return;
        }

        console.log("[Psyonix] Authenticated with servers.")
        callback(JSON.parse(body).Responses[0].Result);
    });
}

steamClient.on('loggedOn', async (details) => {
    var ticket = await steamClient.getEncryptedAppTicket(RLAppId, null);

    getAuthentication(
        ticket, 
        clientSteam.steamID.getSteamID64(), 
        DisplayName, 
        (rl) => {
            console.log(`[Psyonix] Welcome back, ${rl.verified_player_name}`);
    
            var requestId = 0;
            var serviceId = 0;
    
            let websocket = new WebSocket(rl["PerConURL"], {
                headers: {
                    'PsyToken': rl["PsyToken"],
                    'PsySessionID': rl["SessionID"],
                    'PsyBuildID': RLBuildId,
                    'PsyEnvironment': RLEnvironment,
                    'User-Agent': RLUserAgent
                }
            });
    
            websocket.on("open", () => {
                console.log(`[Rocket League] Websocket has been opened to ${rl["PerConUrl"]}`);
    
                client.on('message', function (data) {
                    let start = data.indexOf('\r\n\r\n')
                    if (start !== -1) {
                        start += 4
                        let jsonString = data.substring(start);
                        let jsonPretty = JSON.stringify(JSON.parse(jsonString), null, 2);
                        console.log(jsonPretty);
                    }
                });
    
                console.log('[RocketLeague] Requesting inventory of signed in player..');
    
                let msgBody = JSON.stringify([
                    {
                        Service: 'Products/GetPlayerProducts',
                        Version: 1,
                        ID: serviceId++,
                        Params: {
                            PlayerID: `Steam|${ticket.account_id}|0`
                        }
                    }
                ]);
    
                let msgSignature = createSignature(msgBody);
                let msg = `PsySig: ${msgSignature}\r\n` +
                            `PsyRequestID: PsyNetMessage_X_${requestId++}\r\n` +
                            "\r\n" +
                            msgBody;
    
                client.send(msg);
            });
        }

    );
});
