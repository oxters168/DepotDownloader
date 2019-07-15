using SteamKit2;
using SteamKit2.Unified.Internal;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DepotDownloader
{
    public class Steam3Session
    {
        public class Credentials
        {
            public bool LoggedOn { get; set; }
            public ulong SessionToken { get; set; }
        }

        public ReadOnlyCollection<SteamApps.LicenseListCallback.License> Licenses
        {
            get;
            private set;
        }

        public Dictionary<uint, byte[]> AppTickets { get; private set; }
        public Dictionary<uint, ulong> AppTokens { get; private set; }
        public Dictionary<uint, byte[]> DepotKeys { get; private set; }
        public ConcurrentDictionary<string, SteamApps.CDNAuthTokenCallback> CDNAuthTokens { get; private set; }
        public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> AppInfo { get; private set; }
        public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> PackageInfo { get; private set; }
        public Dictionary<string, byte[]> AppBetaPasswords { get; private set; }

        public SteamClient steamClient;
        public SteamUser steamUser;
        SteamApps steamApps;
        SteamUnifiedMessages.UnifiedService<IPublishedFile> steamPublishedFile;

        CallbackManager callbacks;

        bool authenticatedUser;
        bool bConnected;
        bool bConnecting;
        bool bAborted;
        bool bExpectingDisconnectRemote;
        bool bDidDisconnect;
        int connectionBackoff;
        int seq; // more hack fixes
        DateTime connectTime;

        // input
        SteamUser.LogOnDetails logonDetails;

        // output
        Credentials credentials;
        public bool loggedOn { get { return credentials.LoggedOn; } }

        static readonly TimeSpan STEAM3_TIMEOUT = TimeSpan.FromSeconds( 30 );

        public event LogonFailed tfaRequired, passRequired, authRequired;
        public delegate void LogonFailed();

        public Steam3Session(SteamClient steamClient, CallbackManager callbackManager)
        {
            this.bConnected = false;
            this.bConnecting = false;
            this.bAborted = false;
            this.seq = 0;

            this.steamClient = steamClient;

            this.steamUser = this.steamClient.GetHandler<SteamUser>();
            this.steamApps = this.steamClient.GetHandler<SteamApps>();
            var steamUnifiedMessages = this.steamClient.GetHandler<SteamUnifiedMessages>();
            this.steamPublishedFile = steamUnifiedMessages.CreateService<IPublishedFile>();

            this.callbacks = callbackManager;

            this.callbacks.Subscribe<SteamClient.ConnectedCallback>(ConnectedCallback);
            this.callbacks.Subscribe<SteamClient.DisconnectedCallback>(DisconnectedCallback);
            this.callbacks.Subscribe<SteamUser.LoggedOnCallback>(LogOnCallback);
            this.callbacks.Subscribe<SteamUser.SessionTokenCallback>(SessionTokenCallback);
            this.callbacks.Subscribe<SteamApps.LicenseListCallback>(LicenseListCallback);
            this.callbacks.Subscribe<SteamUser.UpdateMachineAuthCallback>(UpdateMachineAuthCallback);
            this.callbacks.Subscribe<SteamUser.LoginKeyCallback>(LoginKeyCallback);
        }
        public Steam3Session(SteamClient steamClient, CallbackManager callbackManager, SteamUser.LogOnDetails details, string sentryLoc = "") : this(steamClient, callbackManager)
        {
            LoginAs(details, sentryLoc);
        }

        public void LoginAs(SteamUser.LogOnDetails details, string sentryLoc = "")
        {
            this.AppTickets = new Dictionary<uint, byte[]>();
            this.AppTokens = new Dictionary<uint, ulong>();
            this.DepotKeys = new Dictionary<uint, byte[]>();
            this.CDNAuthTokens = new ConcurrentDictionary<string, SteamApps.CDNAuthTokenCallback>();
            this.AppInfo = new Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>();
            this.PackageInfo = new Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>();
            this.AppBetaPasswords = new Dictionary<string, byte[]>();

            this.logonDetails = details;

            this.authenticatedUser = details.Username != null;
            this.credentials = new Credentials();

            if (authenticatedUser)
            {
                FileInfo fi = new FileInfo(Path.Combine(sentryLoc, String.Format("{0}.sentryFile", logonDetails.Username)));
                if (ConfigStore.TheConfig.SentryData != null && ConfigStore.TheConfig.SentryData.ContainsKey(logonDetails.Username))
                {
                    logonDetails.SentryFileHash = Util.SHAHash(ConfigStore.TheConfig.SentryData[logonDetails.Username]);
                }
                else if (fi.Exists && fi.Length > 0)
                {
                    var sentryData = File.ReadAllBytes(fi.FullName);
                    logonDetails.SentryFileHash = Util.SHAHash(sentryData);
                    ConfigStore.TheConfig.SentryData[logonDetails.Username] = sentryData;
                    ConfigStore.Save();
                }
            }

            Console.Write("Connecting to Steam3...");

            Connect();
        }

        /*public delegate bool WaitCondition();
        public bool WaitUntilCallback( Action submitter, WaitCondition waiter )
        {
            while ( !bAborted && !waiter() )
            {
                submitter();

                int seq = this.seq;
                do
                {
                    WaitForCallbacks();
                }
                while ( !bAborted && this.seq == seq && !waiter() );
            }

            return bAborted;
        }*/

        /*public Credentials WaitForCredentials()
        {
            if ( credentials.IsValid || bAborted )
                return credentials;

            routineExecutor.StartCoroutine(CommonRoutines.WaitToDoAction(() => { return credentials.IsValid; }));
            //WaitUntilCallback( () => { }, () => { return credentials.IsValid; } );

            return credentials;
        }*/

        public async Task RequestAppInfo(uint appId)
        {
            bool appTokensReceived = false;
            while (!appTokensReceived)
                appTokensReceived = await RequestAppTokens(appId);

            bool productInfoReceived = false;
            while (!productInfoReceived)
                productInfoReceived = await RequestPICSProductInfo(appId);
        }
        private Task<bool> RequestPICSProductInfo(uint appId)
        {
            var tsc = new TaskCompletionSource<bool>();
            if (AppInfo.ContainsKey(appId) || bAborted)
            {
                tsc.SetResult(true);
                return tsc.Task;
            }
            else
            {
                SteamApps.PICSRequest request = new SteamApps.PICSRequest(appId);
                if (AppTokens.ContainsKey(appId))
                {
                    request.AccessToken = AppTokens[appId];
                    request.Public = false;
                }

                Action<SteamApps.PICSProductInfoCallback> cbMethod = (appInfo) =>
                {
                    foreach (var app_value in appInfo.Apps)
                    {
                        var app = app_value.Value;

                        Console.WriteLine("Got AppInfo for {0}", app.ID);
                        AppInfo.Add(app.ID, app);
                    }

                    foreach (var app in appInfo.UnknownApps)
                    {
                        AppInfo.Add(app, null);
                    }

                    tsc.SetResult(!appInfo.ResponsePending);
                };

                callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<SteamApps.PICSRequest>() { request }, new List<SteamApps.PICSRequest>() { }), cbMethod);

                return tsc.Task;
            }
        }
        private Task<bool> RequestAppTokens(uint appId)
        {
            var tsc = new TaskCompletionSource<bool>();

            if (AppInfo.ContainsKey(appId) || bAborted)
            {
                tsc.SetResult(true);
                return tsc.Task;
            }
            else
            {
                Action<SteamApps.PICSTokensCallback> cbMethodTokens = (appTokens) =>
                {
                    if (appTokens.AppTokensDenied.Contains(appId))
                    {
                        Console.WriteLine("Insufficient privileges to get access token for app {0}", appId);
                    }

                    foreach (var token_dict in appTokens.AppTokens)
                    {
                        this.AppTokens.Add(token_dict.Key, token_dict.Value);
                    }
                    tsc.SetResult(true);
                };

                callbacks.Subscribe(steamApps.PICSGetAccessTokens(new List<uint>() { appId }, new List<uint>() { }), cbMethodTokens);

                return tsc.Task;
            }
        }

        public async Task RequestPackageInfo(IEnumerable<uint> packageIds)
        {
            bool packageInfoReceived = false;
            while (!packageInfoReceived)
                packageInfoReceived = await RequestPackageInfoInside(packageIds);
        }
        private Task<bool> RequestPackageInfoInside(IEnumerable<uint> packageIds)
        {
            var tsc = new TaskCompletionSource<bool>();

            List<uint> packages = packageIds.ToList();
            packages.RemoveAll(pid => PackageInfo.ContainsKey(pid));

            if (packages.Count == 0 || bAborted)
            {
                tsc.SetResult(true);
                return tsc.Task;
            }
            else
            {
                Action<SteamApps.PICSProductInfoCallback> cbMethod = (packageInfo) =>
                {
                    foreach (var package_value in packageInfo.Packages)
                    {
                        var package = package_value.Value;
                        PackageInfo.Add(package.ID, package);
                    }

                    foreach (var package in packageInfo.UnknownPackages)
                    {
                        PackageInfo.Add(package, null);
                    }

                    tsc.SetResult(!packageInfo.ResponsePending);
                };

                callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<uint>(), packages), cbMethod);
                return tsc.Task;
            }
        }

        public Task<bool> RequestFreeAppLicense( uint appId )
        {
            var tsc = new TaskCompletionSource<bool>();

            Action<SteamApps.FreeLicenseCallback> cbMethod = (resultInfo) =>
            {
                tsc.SetResult(resultInfo.GrantedApps.Contains(appId));
            };

            callbacks.Subscribe(steamApps.RequestFreeLicense(appId), cbMethod);
            return tsc.Task;
        }

        public Task<bool> RequestAppTicket(uint appId)
        {
            var tsc = new TaskCompletionSource<bool>();

            if (AppTickets.ContainsKey(appId) || bAborted)
            {
                tsc.SetResult(true);
                return tsc.Task;
            }
            else if (!authenticatedUser)
            {
                tsc.SetResult(true);
                AppTickets[appId] = null;
                return tsc.Task;
            }
            else
            {
                Action<SteamApps.AppOwnershipTicketCallback> cbMethod = (appTicket) =>
                {
                    if (appTicket.Result != EResult.OK)
                    {
                        Console.WriteLine("Unable to get appticket for {0}: {1}", appTicket.AppID, appTicket.Result);
                        Abort();
                    }
                    else
                    {
                        Console.WriteLine("Got appticket for {0}!", appTicket.AppID);
                        AppTickets[appTicket.AppID] = appTicket.Ticket;
                    }
                    tsc.SetResult(true);
                };

                callbacks.Subscribe(steamApps.GetAppOwnershipTicket(appId), cbMethod);
                return tsc.Task;
            }
        }

        public Task<bool> RequestDepotKey( uint depotId, uint appid = 0 )
        {
            var tsc = new TaskCompletionSource<bool>();

            if (DepotKeys.ContainsKey(depotId) || bAborted)
            {
                tsc.SetResult(true);
                return tsc.Task;
            }
            else
            {

                Action<SteamApps.DepotKeyCallback> cbMethod = (depotKey) =>
                {
                    Console.WriteLine("Got depot key for {0} result: {1}", depotKey.DepotID, depotKey.Result);

                    if (depotKey.Result != EResult.OK)
                    {
                        Abort();
                        return;
                    }

                    DepotKeys[depotKey.DepotID] = depotKey.DepotKey;
                    tsc.SetResult(true);
                };

                callbacks.Subscribe(steamApps.GetDepotDecryptionKey(depotId, appid), cbMethod);
                return tsc.Task;
            }
        }

        public string ResolveCDNTopLevelHost(string host)
        {
            // SteamPipe CDN shares tokens with all hosts
            if (host.EndsWith( ".steampipe.steamcontent.com" ) )
            {
                return "steampipe.steamcontent.com";
            }

            return host;
        }

        public Task<bool> RequestCDNAuthToken(uint appid, uint depotid, string host)
        {
            var tsc = new TaskCompletionSource<bool>();

            host = ResolveCDNTopLevelHost( host );
            var cdnKey = string.Format( "{0:D}:{1}", depotid, host );

            if (CDNAuthTokens.ContainsKey(cdnKey) || bAborted)
            {
                tsc.SetResult(true);
                return tsc.Task;
            }
            else
            {
                Action<SteamApps.CDNAuthTokenCallback> cbMethod = (cdnAuth) =>
                {
                    Console.WriteLine("Got CDN auth token for {0} result: {1} (expires {2})", host, cdnAuth.Result, cdnAuth.Expiration);

                    if (cdnAuth.Result != EResult.OK)
                    {
                        Abort();
                        return;
                    }

                    CDNAuthTokens.TryAdd(cdnKey, cdnAuth);

                    tsc.SetResult(true);
                };

                callbacks.Subscribe(steamApps.GetCDNAuthToken(appid, depotid, host), cbMethod);
                return tsc.Task;
            }
        }

        public Task<bool> CheckAppBetaPassword(uint appid, string password)
        {
            var tsc = new TaskCompletionSource<bool>();

            Action<SteamApps.CheckAppBetaPasswordCallback> cbMethod = ( appPassword ) =>
            {
                Console.WriteLine( "Retrieved {0} beta keys with result: {1}", appPassword.BetaPasswords.Count, appPassword.Result );

                foreach (var entry in appPassword.BetaPasswords)
                {
                    AppBetaPasswords[entry.Key] = entry.Value;
                }
                tsc.SetResult(true);
            };

            callbacks.Subscribe(steamApps.CheckAppBetaPassword(appid, password), cbMethod);
            return tsc.Task;
        }

        public Task<PublishedFileDetails> GetPubfileDetails(PublishedFileID pubFile)
        {
            var tsc = new TaskCompletionSource<PublishedFileDetails>();

            var pubFileRequest = new CPublishedFile_GetDetails_Request();
            pubFileRequest.publishedfileids.Add( pubFile );

            Action<SteamUnifiedMessages.ServiceMethodResponse> cbMethod = callback =>
            {
                if ( callback.Result == EResult.OK )
                {
                    var response = callback.GetDeserializedResponse<CPublishedFile_GetDetails_Response>();
                    tsc.SetResult(response.publishedfiledetails[0]);
                }
                else
                {
                    tsc.SetResult(null);
                    throw new Exception( $"EResult {(int)callback.Result} ({callback.Result}) while retrieving UGC id for pubfile {pubFile}.");
                }
            };

            callbacks.Subscribe(steamPublishedFile.SendMessage(api => api.GetDetails(pubFileRequest)), cbMethod);
            return tsc.Task;
        }

        void Connect()
        {
            bAborted = false;
            bConnected = false;
            bConnecting = true;
            connectionBackoff = 0;
            bExpectingDisconnectRemote = false;
            bDidDisconnect = false;
            this.connectTime = DateTime.Now;
            this.steamClient.Connect();
        }

        private void Abort( bool sendLogOff = true )
        {
            Disconnect( sendLogOff );
        }
        public void Disconnect( bool sendLogOff = true )
        {
            if ( sendLogOff )
            {
                steamUser.LogOff();
            }

            steamClient.Disconnect();
            bConnected = false;
            bConnecting = false;
            bAborted = true;
        }

        public Task<bool> TryWaitForLoginKey()
        {
            var tsc = new TaskCompletionSource<bool>();

            if (logonDetails.Username == null || !logonDetails.ShouldRememberPassword)
            {
                tsc.SetResult(true);
                return tsc.Task;
            }
            else
            {
                tsc.Task.Wait(TimeSpan.FromSeconds(10));
                tsc.SetResult(ConfigStore.TheConfig.LoginKeys.ContainsKey(logonDetails.Username));

                return tsc.Task;
            }
        }

        /*private void WaitForCallbacks()
        {
            callbacks.RunWaitCallbacks( TimeSpan.FromSeconds( 1 ) );

            TimeSpan diff = DateTime.Now - connectTime;

            if ( diff > STEAM3_TIMEOUT && !bConnected )
            {
                Console.WriteLine( "Timeout connecting to Steam3." );
                Abort();

                return;
            }
        }*/

        private void ConnectedCallback( SteamClient.ConnectedCallback connected )
        {
            Console.WriteLine( " Done!" );
            bConnecting = false;
            bConnected = true;
            if ( !authenticatedUser )
            {
                Console.Write( "Logging anonymously into Steam3..." );
                steamUser.LogOnAnonymous();
            }
            else
            {
                Console.Write( "Logging '{0}' into Steam3...", logonDetails.Username );
                steamUser.LogOn( logonDetails );
            }
        }

        private void DisconnectedCallback( SteamClient.DisconnectedCallback disconnected )
        {
            bDidDisconnect = true;

            if ( disconnected.UserInitiated || bExpectingDisconnectRemote )
            {
                Console.WriteLine( "Disconnected from Steam" );
            }
            else if ( connectionBackoff >= 10 )
            {
                Console.WriteLine( "Could not connect to Steam after 10 tries" );
                Abort( false );
            }
            else if ( !bAborted )
            {
                if ( bConnecting )
                {
                    Console.WriteLine( "Connection to Steam failed. Trying again" );
                }
                else
                {
                    Console.WriteLine( "Lost connection to Steam. Reconnecting" );
                }

                Thread.Sleep( 1000 * ++connectionBackoff );
                steamClient.Connect();
            }
        }

        private void LogOnCallback( SteamUser.LoggedOnCallback loggedOn )
        {
            bool isSteamGuard = loggedOn.Result == EResult.AccountLogonDenied;
            bool is2FA = loggedOn.Result == EResult.AccountLoginDeniedNeedTwoFactor;
            bool isLoginKey = logonDetails.ShouldRememberPassword && logonDetails.LoginKey != null && loggedOn.Result == EResult.InvalidPassword;

            if ( isSteamGuard || is2FA || isLoginKey )
            {
                bExpectingDisconnectRemote = true;
                Abort( false );

                if ( !isLoginKey )
                {
                    Console.WriteLine( "This account is protected by Steam Guard." );
                }

                if ( is2FA )
                {
                    Console.Write( "Please enter your 2 factor auth code from your authenticator app: " );
                    tfaRequired?.Invoke();
                    //logonDetails.TwoFactorCode = Console.ReadLine();
                }
                else if ( isLoginKey )
                {
                    ConfigStore.TheConfig.LoginKeys.Remove( logonDetails.Username );
                    ConfigStore.Save();

                    logonDetails.LoginKey = null;

                    Console.WriteLine( "Login key was expired. Please enter your password: " );
                    passRequired?.Invoke();
                    //logonDetails.Password = Util.ReadPassword();
                }
                else
                {
                    Console.Write( "Please enter the authentication code sent to your email address: " );
                    authRequired?.Invoke();
                    //logonDetails.AuthCode = Console.ReadLine();
                }

                //Console.Write( "Retrying Steam3 connection..." );
                //Connect();

                return;
            }
            else if ( loggedOn.Result == EResult.ServiceUnavailable )
            {
                Console.WriteLine( "Unable to login to Steam3: {0}", loggedOn.Result );
                Abort( false );

                return;
            }
            else if ( loggedOn.Result != EResult.OK )
            {
                Console.WriteLine( "Unable to login to Steam3: {0}", loggedOn.Result );
                Abort();

                return;
            }

            Console.WriteLine( " Done!" );

            this.seq++;
            credentials.LoggedOn = true;

            if ( ContentDownloader.Config.CellID == 0 )
            {
                Console.WriteLine( "Using Steam3 suggested CellID: " + loggedOn.CellID );
                ContentDownloader.Config.CellID = ( int )loggedOn.CellID;
            }
        }
        public void SendTwoFactor(string code)
        {
            logonDetails.TwoFactorCode = code;
            Connect();
        }
        public void ResendPassword(string password)
        {
            logonDetails.Password = password;
            Connect();
        }
        public void SendAuth(string code)
        {
            logonDetails.AuthCode = code;
            Connect();
        }

        private void SessionTokenCallback( SteamUser.SessionTokenCallback sessionToken )
        {
            Console.WriteLine( "Got session token!" );
            credentials.SessionToken = sessionToken.SessionToken;
        }

        private void LicenseListCallback( SteamApps.LicenseListCallback licenseList )
        {
            if ( licenseList.Result != EResult.OK )
            {
                Console.WriteLine( "Unable to get license list: {0} ", licenseList.Result );
                Abort();

                return;
            }

            Console.WriteLine( "Got {0} licenses for account!", licenseList.LicenseList.Count );
            Licenses = licenseList.LicenseList;
        }

        private void UpdateMachineAuthCallback( SteamUser.UpdateMachineAuthCallback machineAuth )
        {
            byte[] hash = Util.SHAHash( machineAuth.Data );
            Console.WriteLine( "Got Machine Auth: {0} {1} {2} {3}", machineAuth.FileName, machineAuth.Offset, machineAuth.BytesToWrite, machineAuth.Data.Length, hash );

            ConfigStore.TheConfig.SentryData[ logonDetails.Username ] = machineAuth.Data;
            ConfigStore.Save();

            var authResponse = new SteamUser.MachineAuthDetails
            {
                BytesWritten = machineAuth.BytesToWrite,
                FileName = machineAuth.FileName,
                FileSize = machineAuth.BytesToWrite,
                Offset = machineAuth.Offset,

                SentryFileHash = hash, // should be the sha1 hash of the sentry file we just wrote

                OneTimePassword = machineAuth.OneTimePassword, // not sure on this one yet, since we've had no examples of steam using OTPs

                LastError = 0, // result from win32 GetLastError
                Result = EResult.OK, // if everything went okay, otherwise ~who knows~

                JobID = machineAuth.JobID, // so we respond to the correct server job
            };

            // send off our response
            steamUser.SendMachineAuthResponse( authResponse );
        }

        private void LoginKeyCallback( SteamUser.LoginKeyCallback loginKey )
        {
            Console.WriteLine( "Accepted new login key for account {0}", logonDetails.Username );

            ConfigStore.TheConfig.LoginKeys[ logonDetails.Username ] = loginKey.LoginKey;
            ConfigStore.Save();

            steamUser.AcceptNewLoginKey( loginKey );
        }
    }
}
