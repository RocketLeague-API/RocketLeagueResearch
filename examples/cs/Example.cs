public class PsyBody
{

    public string Service { get; set; }
    public int Version { get; set; }

    [JsonPropertyName("ID")]
    public int Id { get; set; }

    public object Params { get; set; }

}

public class PsyResponses<T>
{
    public PsyResponse<T>[] Responses { get; set; }
}

public class PsyResponse<T>
{

    [JsonPropertyName("ID")]
    public int Id { get; set; }

    public T Result { get; set; }

}

public class PsyAuthResponse
{

    [JsonPropertyName("SessionID")]
    public string SessionId { get; set; }

    public string VerifiedPlayerName { get; set; }

    [JsonPropertyName("PerConURL")]
    public string PerConUrl { get; set; }

    [JsonPropertyName("PerConURLv2")]
    public string PerConUrlV2 { get; set; }

    public string PsyToken { get; set; }
    public PsyTag PsyTag { get; set; }
    
    public bool IsLastChanceAuthBan { get; set; }

}

public class Device
{

    public string DeviceId { get; set; }
    public string AccountId { get; set; }
    public string Secret { get; set; }

}

// TODO: Fix authentication responses
public class AuthenticationResponse
{

    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("account_id")]
    public string AccountId { get; set; }

    [JsonPropertyName("displayName")]
    public string DisplayName { get; set; }

}

public class ExchangeCodeResponse
{

    public string Code { get; set; }

}

public class ExternalAuthResponse
{

    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
    
    [JsonPropertyName("product_user_id")]
    public string ProductUserId { get; set; }
    
    [JsonPropertyName("deployment_id")]
    public string DeploymentId { get; set; }

}

public class RocketLeagueApi : IDisposable
{

    private const int ResponseTimeout = 5000;

    private static readonly JsonSerializerOptions JsonSerializerSettings = new()
    {
        PropertyNameCaseInsensitive = true,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
        WriteIndented = false
    };

    public event Func<string, string, Task> LoggedIn; 

    public string AccountId => _externalAuth.AccountId;
    public string AccountDisplayName => _auth.DisplayName;

    private readonly SkillsService _skillsService;

    /// <summary>
    /// All services for player stats 
    /// </summary>
    public SkillsService SkillsService
    {
        get
        {
            if (!_websocketClient.IsConnected)
            {
                throw new RocketLeagueApiException("Tried accessing a service without open connection.");
            }

            return _skillsService;
        }
    }

    internal int RequestIdCounter { get; set; }
    internal int ServiceIdCounter { get; set; } = 1;

    private readonly RocketLeagueApiOptions _options;
    private readonly Ws4NetClient _websocketClient;
    public readonly EpicGamesService _epicGamesService;

    private AuthenticationResponse _auth;
    private AuthenticationResponse _externalAuth;

    public RocketLeagueApi(Action<RocketLeagueApiOptions> optionsAction)
    {
        _options = new RocketLeagueApiOptions();
        optionsAction(_options);

        _websocketClient = new Ws4NetClient();
        _epicGamesService = new EpicGamesService(this);

        _skillsService = new SkillsService(this);
    }

    /// <summary>
    /// Logs in with Epic Games, this should be called before <see cref="StartAsync"/>
    /// It will login with the grant type provided in the <see cref="RocketLeagueApiOptions"/> in the constructor
    /// </summary>
    /// <returns>Task</returns>
    public async Task LoginAsync(CancellationToken ct = default)
    {
        switch (_options.GrantType)
        {
            case GrantType.AuthCode:
                if (string.IsNullOrEmpty(_options.AuthCode))
                {
                    throw new RocketLeagueApiException(
                        "Tried to authenticate with authorization code, but no code was provided in the options.");
                }

                _auth = await _epicGamesService.AuthAuthorizationCodeAsync(_options.AuthCode, ct)
                    .ConfigureAwait(false);
                break;
            case GrantType.ExchangeCode:
                if (string.IsNullOrEmpty(_options.ExchangeCode))
                {
                    throw new RocketLeagueApiException(
                        "Tried to authenticate with exchange code, but no exchange code was provided in the options.");
                }

                _auth = await _epicGamesService.ExchangeCodeAuthAsync(_options.ExchangeCode, ct)
                    .ConfigureAwait(false);
                break;
            case GrantType.Device:
                var device = _options.Device;
                if (device == null)
                {
                    throw new RocketLeagueApiException(
                        "Tried to authenticate with device, but no device was provided in the options.");
                }

                _auth = await _epicGamesService.GetAccessTokenAsync("device_auth", ct,
                    ("device_id", _options.Device.DeviceId),
                    ("account_id", _options.Device.AccountId),
                    ("secret", _options.Device.Secret)).ConfigureAwait(false);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }

        ExchangeCodeResponse exchangeCodeResponse = null;
        if (_options.GrantType != GrantType.ExchangeCode)
        {
            exchangeCodeResponse = await _epicGamesService.GetExchangeTokenAsync(_auth, ct).ConfigureAwait(false);
        }

        _externalAuth = await _epicGamesService.GetExternalAuthAsync(exchangeCodeResponse, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Authenticates with Psyonix and connects to their websocket, this method requires epic games to be logged in.
    /// <see cref="LoginAsync"/>
    /// </summary>
    /// <returns>Task</returns>
    public Task StartAsync()
    {
        if (_externalAuth == null)
        {
            throw new RocketLeagueApiException(
                "Tried starting the rocket league api without logging in to epic games.");
        }

        return PsyLoginAsync();
    }

    internal async Task<T> RequestAsync<T>(PsyBody[] body, int id)
    {
        var (signature, serialized) = SignBodies(body);
        var headers = $"PsySig: {signature}\r\nPsyRequestID: PsyNetMessage_X_{RequestIdCounter++}\r\n\r\n";
        var finalMessage = $"{headers}{serialized}";
        var finalMessageData = Encoding.UTF8.GetBytes(finalMessage);

        var cts = new CancellationTokenSource(ResponseTimeout);
        PsyResponse<T> response = null;
        _websocketClient.TextMessage += OnReceiveAsync;

        Task OnReceiveAsync(string message)
        {
            try
            {
                var idx = message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                var json = message[(idx + 4)..];
                var responses = JsonSerializer.Deserialize<PsyResponses<T>>(json, JsonSerializerSettings);
                if (responses == null)
                {
                    throw new JsonException("Something went wrong serializing websocket response.");
                }

                response = responses.Responses.First(x => x.Id == id);
            }
            catch
            {
                // ignored
            }

            cts.Cancel();
            return Task.CompletedTask;
        }

        try
        {
            await _websocketClient.SendAsync(finalMessageData, 0, finalMessageData.Length, true);

            try
            {
                await Task.Delay(-1, cts.Token);
            }
            catch
            {
                // ignored
            }
        }
        finally
        {
            _websocketClient.TextMessage -= OnReceiveAsync;
        }

        return response.Result;
    }

    private async Task PsyLoginAsync()
    {
        var client = new RestClient(Globals.RlBaseUrl);
        var request = new RestRequest("/Services", Method.Post);
        var body = new PsyBody
        {
            Service = "Auth/AuthPlayer",
            Version = 2,
            Id = ServiceIdCounter++,
            Params = new PsyLoginBody
            {
                EpicAccountId = _externalAuth.AccountId,
                EpicAuthTicket = _externalAuth.AccessToken
            }
        };

        var (signature, serialized) = SignBody(body);
        request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
        request.AddHeader("User-Agent", "RL WIN/220224.66435.368596 gzip");
        request.AddHeader("PsyBuildID", Globals.PsyBuildId);
        request.AddHeader("PsyEnvironment", Globals.PsyEnvironment);
        request.AddHeader("PsyRequestID", $"PsyNetMessage_X_{RequestIdCounter++}");
        request.AddHeader("PsySig", signature);
        request.AddStringBody(serialized, "application/x-www-form-urlencoded");

        var response = await client.ExecuteAsync<PsyResponses<PsyAuthResponse>>(request);
        var data = response.Data!.Responses.First();
        var result = data.Result;
        _websocketClient.SetHeader("User-Agent", "RL WIN/220224.66435.368596 gzip");
        _websocketClient.SetHeader("PsyToken", result.PsyToken);
        _websocketClient.SetHeader("PsySessionID", result.SessionId);
        _websocketClient.SetHeader("PsyBuildID", Globals.PsyBuildId);
        _websocketClient.SetHeader("PsyEnvironment", Globals.PsyEnvironment);

        await _websocketClient.ConnectAsync(result.PerConUrl)
            .ConfigureAwait(false);

        LoggedIn?.Invoke(AccountId, AccountDisplayName);
    }

    private static (string Signature, string Serialized) SignBody(PsyBody body)
    {
        return SignBodies(new[] {body});
    }

    private static (string Signature, string Serialized) SignBodies(PsyBody[] bodies)
    {
        var bodySerialized = JsonSerializer.Serialize(bodies, JsonSerializerSettings);
        var signature = CalcHmacsha256Hash($"-{bodySerialized}", Globals.RlHmacSha256Str);
        var signatureHex = Convert.FromHexString(signature);
        var signatureBase64 = Convert.ToBase64String(signatureHex);

        return (signatureBase64, bodySerialized);
    }

    private static string CalcHmacsha256Hash(string content, string key)
    {
        var enc = Encoding.Default;
        byte[] baText2BeHashed = enc.GetBytes(content),
            baSalt = enc.GetBytes(key);
        var hasher = new HMACSHA256(baSalt);
        var baHashedText = hasher.ComputeHash(baText2BeHashed);
        var result = string.Join("", baHashedText.ToList().Select(b => b.ToString("x2")).ToArray());
        return result;
    }

    private bool _isDisposed;

    ~RocketLeagueApi()
    {
        Dispose(false);
    }

    private void Dispose(bool disposing)
    {
        if (!_isDisposed)
        {
            if (disposing)
            {
                _websocketClient?.Dispose();
            }

            _isDisposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

}

public class EpicGamesService
{

    private readonly RocketLeagueApi _api;

    public EpicGamesService(RocketLeagueApi api)
    {
        _api = api;
    }

    // TODO: Fix create device
    public async Task<Device> CreateDeviceAsync(AuthenticationResponse authResponse)
    {
        var client = new RestClient("https://account-public-service-prod.ol.epicgames.com");

        var request = new RestRequest($"/account/api/public/account/{authResponse.AccountId}/deviceAuth", Method.Post);
        request.AddHeader("Authorization", $"Bearer {authResponse.AccessToken}");

        var response = await client.ExecuteAsync<Device>(request);
        return response.Data;
    }

    public Task<AuthenticationResponse> ExchangeCodeAuthAsync(string exchangeCode, CancellationToken ct = default)
    {
        return GetAccessTokenAsync("exchange_code", ct, ("exchange_code", exchangeCode));
    }

    public async Task<AuthenticationResponse> GetAccessTokenAsync(string grantType, CancellationToken ct = default, params(string K, string V)[] fields)
    {
        var client = new RestClient("https://account-public-service-prod.ol.epicgames.com/account");

        var request = new RestRequest("/api/oauth/token", Method.Post);
        request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
        request.AddHeader("Authorization", $"basic {Globals.IosClientToken}");

        request.AddParameter("grant_type", grantType);
        foreach (var (k, v) in fields)
        {
            request.AddParameter(k, v);
        }

        var response = await client.ExecuteAsync<AuthenticationResponse>(request, ct);
        return response.Data;
    }

    public async Task<AuthenticationResponse> GetExternalAuthAsync(ExchangeCodeResponse exchangeResponse, CancellationToken ct = default)
    {
        var client = new RestClient("https://api.epicgames.dev");

        var request = new RestRequest("/epic/oauth/v1/token", Method.Post);
        request.AddHeader("Authorization", $"Basic {Globals.RlClientToken}");
        request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
        request.AddParameter("deployment_id", Globals.RlDeploymentId);
        request.AddParameter("grant_type", "exchange_code");
        request.AddParameter("exchange_code", exchangeResponse.Code);
        request.AddParameter("scope", "basic_profile friends_list presence");

        var response = await client.ExecuteAsync<AuthenticationResponse>(request, ct)
            .ConfigureAwait(false);

        return response.Data;
    }

    public async Task<ExternalAuthResponse> GetUserAuthTokenAsync(AuthenticationResponse authResponse, CancellationToken ct = default)
    {
        var client = new RestClient("https://api.epicgames.dev");

        var request = new RestRequest("/auth/v1/oauth/token", Method.Post);
        request.AddHeader("Authorization", $"Basic {Globals.RlClientToken}");
        request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
        request.AddParameter("deployment_id", Globals.RlDeploymentId);
        request.AddParameter("nonce", "2W5vgU-FxESeNw2tADe2Zg");
        request.AddParameter("external_auth_type", "epicgames_access_token");
        request.AddParameter("grant_type", "external_auth");
        request.AddParameter("external_auth_token", authResponse.AccessToken);

        var response = await client.ExecuteAsync<ExternalAuthResponse>(request, ct)
            .ConfigureAwait(false);
        return response.Data;
    }

    public async Task<ExchangeCodeResponse> GetExchangeTokenAsync(AuthenticationResponse authResponse, CancellationToken ct = default)
    {
        var client = new RestClient("https://account-public-service-prod.ol.epicgames.com");
        var request = new RestRequest("/account/api/oauth/exchange");
        request.AddHeader("Authorization", $"Bearer {authResponse.AccessToken}");

        var response = await client.ExecuteAsync<ExchangeCodeResponse>(request, ct)
            .ConfigureAwait(false);
        return response.Data;
    }

    public async Task<AuthenticationResponse> AuthAuthorizationCodeAsync(string authCode, CancellationToken ct = default)
    {
        var client = new RestClient("https://account-public-service-prod.ol.epicgames.com");
        var request = new RestRequest("/account/api/oauth/token", Method.Post);
        request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
        request.AddHeader("Authorization", $"basic {Globals.IosClientToken}");

        request.AddParameter("grant_type", "authorization_code");
        request.AddParameter("code", authCode);

        var response = await client.ExecuteAsync<AuthenticationResponse>(request, ct)
            .ConfigureAwait(false);
        return response.Data;
    }

}