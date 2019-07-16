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

            SteamController.LogToConsole("Connecting to Steam3...");

            Connect();
        }

        public async Task RequestAppInfo(uint appId)
        {
            if (!AppInfo.ContainsKey(appId) && !bAborted)
            {
                bool appTokensReceived = false;
                while (!bAborted && !appTokensReceived)
                    appTokensReceived = await RequestAppTokens(appId);

                bool productInfoReceived = false;
                while (!bAborted && !productInfoReceived)
                    productInfoReceived = await RequestPICSProductInfo(appId);
            }
        }
        private Task<bool> RequestPICSProductInfo(uint appId)
        {
            var tsc = new TaskCompletionSource<bool>();

            SteamApps.PICSRequest request = new SteamApps.PICSRequest(appId);
            if (AppTokens.ContainsKey(appId))
            {
                request.AccessToken = AppTokens[appId];
                request.Public = false;
            }

            IDisposable subscription = null;
            Action<SteamApps.PICSProductInfoCallback> cbMethod = (appInfo) =>
            {
                foreach (var app_value in appInfo.Apps)
                {
                    var app = app_value.Value;

                    SteamController.LogToConsole("Got AppInfo for " + app.ID);
                    AppInfo.Add(app.ID, app);
                }

                foreach (var app in appInfo.UnknownApps)
                {
                    AppInfo.Add(app, null);
                }

                tsc.SetResult(!appInfo.ResponsePending);
                subscription.Dispose();
            };

            subscription = callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<SteamApps.PICSRequest>() { request }, new List<SteamApps.PICSRequest>() { }), cbMethod);

            return tsc.Task;
        }
        private Task<bool> RequestAppTokens(uint appId)
        {
            var tsc = new TaskCompletionSource<bool>();

            IDisposable subscription = null;
            Action<SteamApps.PICSTokensCallback> cbMethodTokens = (appTokens) =>
            {
                if (appTokens.AppTokensDenied.Contains(appId))
                {
                    SteamController.LogToConsole("Insufficient privileges to get access token for app " + appId);
                }

                foreach (var token_dict in appTokens.AppTokens)
                {
                    this.AppTokens.Add(token_dict.Key, token_dict.Value);
                }
                tsc.SetResult(true);
                subscription.Dispose();
            };

            subscription = callbacks.Subscribe(steamApps.PICSGetAccessTokens(new List<uint>() { appId }, new List<uint>() { }), cbMethodTokens);

            return tsc.Task;
        }

        public async Task RequestPackageInfo(IEnumerable<uint> packageIds)
        {
            List<uint> packages = packageIds.ToList();
            packages.RemoveAll(pid => PackageInfo.ContainsKey(pid));

            bool packageInfoReceived = false;
            while (!bAborted && !packageInfoReceived && packages.Count > 0)
            {
                packageInfoReceived = await RequestPackageInfoInside(packages);
                packages.RemoveAll(pid => PackageInfo.ContainsKey(pid));
            }
        }
        private Task<bool> RequestPackageInfoInside(IEnumerable<uint> packages)
        {
            var tsc = new TaskCompletionSource<bool>();

            IDisposable subscription = null;
            Action<SteamApps.PICSProductInfoCallback> cbMethod = (packageInfo) =>
            {
                foreach (var package_value in packageInfo.Packages)
                {
                    var package = package_value.Value;
                    PackageInfo.Add(package.ID, package);
                    //PackageInfo[package.ID] = package;
                }

                foreach (var package in packageInfo.UnknownPackages)
                {
                    PackageInfo.Add(package, null);
                    //PackageInfo[package] = null;
                }

                SteamController.LogToConsole("Package info response pending: " + packageInfo.ResponsePending);
                tsc.SetResult(!packageInfo.ResponsePending);
                subscription.Dispose();
            };

            subscription = callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<uint>(), packages), cbMethod);
            return tsc.Task;
        }

        public Task<bool> RequestFreeAppLicense( uint appId )
        {
            var tsc = new TaskCompletionSource<bool>();

            IDisposable subscription = null;
            Action<SteamApps.FreeLicenseCallback> cbMethod = (resultInfo) =>
            {
                tsc.SetResult(resultInfo.GrantedApps.Contains(appId));
                subscription.Dispose();
            };

            subscription = callbacks.Subscribe(steamApps.RequestFreeLicense(appId), cbMethod);
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
                IDisposable subscription = null;
                Action<SteamApps.AppOwnershipTicketCallback> cbMethod = (appTicket) =>
                {
                    if (appTicket.Result != EResult.OK)
                    {
                        SteamController.LogToConsole("Unable to get appticket for " + appTicket.AppID + ": " + appTicket.Result);
                        Abort();
                    }
                    else
                    {
                        SteamController.LogToConsole("Got appticket for " + appTicket.AppID);
                        AppTickets[appTicket.AppID] = appTicket.Ticket;
                    }
                    tsc.SetResult(true);
                    subscription.Dispose();
                };

                subscription = callbacks.Subscribe(steamApps.GetAppOwnershipTicket(appId), cbMethod);
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
                IDisposable subscription = null;
                Action<SteamApps.DepotKeyCallback> cbMethod = (depotKey) =>
                {
                    SteamController.LogToConsole("Got depot key for " + depotKey.DepotID + " result: " + depotKey.Result);

                    if (depotKey.Result != EResult.OK)
                    {
                        Abort();
                        return;
                    }

                    DepotKeys[depotKey.DepotID] = depotKey.DepotKey;
                    tsc.SetResult(true);
                    subscription.Dispose();
                };

                subscription = callbacks.Subscribe(steamApps.GetDepotDecryptionKey(depotId, appid), cbMethod);
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
                IDisposable subscription = null;
                Action<SteamApps.CDNAuthTokenCallback> cbMethod = (cdnAuth) =>
                {
                    SteamController.LogToConsole("Got CDN auth token for " + host + " result: " + cdnAuth.Result + " (expires " + cdnAuth.Expiration + ")");

                    if (cdnAuth.Result != EResult.OK)
                    {
                        Abort();
                        return;
                    }

                    CDNAuthTokens.TryAdd(cdnKey, cdnAuth);

                    tsc.SetResult(true);
                    subscription.Dispose();
                };

                subscription = callbacks.Subscribe(steamApps.GetCDNAuthToken(appid, depotid, host), cbMethod);
                return tsc.Task;
            }
        }

        public Task<bool> CheckAppBetaPassword(uint appid, string password)
        {
            var tsc = new TaskCompletionSource<bool>();

            IDisposable subscription = null;
            Action<SteamApps.CheckAppBetaPasswordCallback> cbMethod = ( appPassword ) =>
            {
                SteamController.LogToConsole("Retrieved " + appPassword.BetaPasswords.Count + " beta keys with result: " + appPassword.Result);

                foreach (var entry in appPassword.BetaPasswords)
                {
                    AppBetaPasswords[entry.Key] = entry.Value;
                }
                tsc.SetResult(true);
                subscription.Dispose();
            };

            subscription = callbacks.Subscribe(steamApps.CheckAppBetaPassword(appid, password), cbMethod);
            return tsc.Task;
        }

        public Task<PublishedFileDetails> GetPubfileDetails(PublishedFileID pubFile)
        {
            var tsc = new TaskCompletionSource<PublishedFileDetails>();

            var pubFileRequest = new CPublishedFile_GetDetails_Request();
            pubFileRequest.publishedfileids.Add( pubFile );

            IDisposable subscription = null;
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
                subscription.Dispose();
            };

            subscription = callbacks.Subscribe(steamPublishedFile.SendMessage(api => api.GetDetails(pubFileRequest)), cbMethod);
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

        private void ConnectedCallback( SteamClient.ConnectedCallback connected )
        {
            SteamController.LogToConsole( " Done!" );
            bConnecting = false;
            bConnected = true;
            if ( !authenticatedUser )
            {
                SteamController.LogToConsole( "Logging anonymously into Steam3..." );
                steamUser.LogOnAnonymous();
            }
            else
            {
                SteamController.LogToConsole( "Logging '" + logonDetails.Username + "' into Steam3...");
                steamUser.LogOn( logonDetails );
            }
        }

        private void DisconnectedCallback( SteamClient.DisconnectedCallback disconnected )
        {
            bDidDisconnect = true;

            if ( disconnected.UserInitiated || bExpectingDisconnectRemote )
            {
                SteamController.LogToConsole( "Disconnected from Steam" );
            }
            else if ( connectionBackoff >= 10 )
            {
                SteamController.LogToConsole( "Could not connect to Steam after 10 tries" );
                Abort( false );
            }
            else if ( !bAborted )
            {
                if ( bConnecting )
                {
                    SteamController.LogToConsole( "Connection to Steam failed. Trying again" );
                }
                else
                {
                    SteamController.LogToConsole( "Lost connection to Steam. Reconnecting" );
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
                    SteamController.LogToConsole( "This account is protected by Steam Guard." );
                }

                if ( is2FA )
                {
                    SteamController.LogToConsole( "Please enter your 2 factor auth code from your authenticator app: " );
                    tfaRequired?.Invoke();
                    //logonDetails.TwoFactorCode = Console.ReadLine();
                }
                else if ( isLoginKey )
                {
                    ConfigStore.TheConfig.LoginKeys.Remove( logonDetails.Username );
                    ConfigStore.Save();

                    logonDetails.LoginKey = null;

                    SteamController.LogToConsole( "Login key was expired. Please enter your password: " );
                    passRequired?.Invoke();
                    //logonDetails.Password = Util.ReadPassword();
                }
                else
                {
                    SteamController.LogToConsole( "Please enter the authentication code sent to your email address: " );
                    authRequired?.Invoke();
                    //logonDetails.AuthCode = Console.ReadLine();
                }

                //SteamController.LogToConsole( "Retrying Steam3 connection..." );
                //Connect();

                return;
            }
            else if ( loggedOn.Result == EResult.ServiceUnavailable )
            {
                SteamController.LogToConsole("Unable to login to Steam3: " + loggedOn.Result );
                Abort( false );

                return;
            }
            else if ( loggedOn.Result != EResult.OK )
            {
                SteamController.LogToConsole("Unable to login to Steam3: " + loggedOn.Result );
                Abort();

                return;
            }

            SteamController.LogToConsole( " Done!" );

            credentials.LoggedOn = true;

            if ( ContentDownloader.Config.CellID == 0 )
            {
                SteamController.LogToConsole( "Using Steam3 suggested CellID: " + loggedOn.CellID );
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
            SteamController.LogToConsole( "Got session token!" );
            credentials.SessionToken = sessionToken.SessionToken;
        }

        private void LicenseListCallback( SteamApps.LicenseListCallback licenseList )
        {
            if ( licenseList.Result != EResult.OK )
            {
                SteamController.LogToConsole( "Unable to get license list: " + licenseList.Result );
                Abort();

                return;
            }

            SteamController.LogToConsole("Got " + licenseList.LicenseList.Count + " licenses for account!");
            Licenses = licenseList.LicenseList;
        }

        private void UpdateMachineAuthCallback( SteamUser.UpdateMachineAuthCallback machineAuth )
        {
            byte[] hash = Util.SHAHash( machineAuth.Data );
            SteamController.LogToConsole("Got Machine Auth: " + machineAuth.FileName + " " + machineAuth.Offset + " " + machineAuth.BytesToWrite + " " + machineAuth.Data.Length + " " + hash);

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
            SteamController.LogToConsole("Accepted new login key for account " + logonDetails.Username );

            ConfigStore.TheConfig.LoginKeys[ logonDetails.Username ] = loginKey.LoginKey;
            ConfigStore.Save();

            steamUser.AcceptNewLoginKey( loginKey );
        }
    }
}
