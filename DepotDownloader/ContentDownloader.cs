using SteamKit2;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DepotDownloader
{
    public static class ContentDownloader
    {
        public const uint INVALID_APP_ID = uint.MaxValue;
        public const uint INVALID_DEPOT_ID = uint.MaxValue;
        public const ulong INVALID_MANIFEST_ID = ulong.MaxValue;
        public const string DEFAULT_BRANCH = "Public";
        private const string DEBUG_NAME_FILES = "ContentDownloaderFiles";

        public static DownloadConfig Config = new DownloadConfig();

        private static CDNClientPool cdnPool;

        private const string DEFAULT_DOWNLOAD_DIR = "depots";
        private const string CONFIG_DIR = ".DepotDownloader";
        private static readonly string STAGING_DIR = Path.Combine( CONFIG_DIR, "staging" );

        private static ulong complete_download_size;
        private static ulong size_downloaded;
        public static bool IsDownloading { get; private set; }
        public static float DownloadPercent { get { return (float)size_downloaded / complete_download_size; } }

        public static event ManifestReceivedHandler onManifestReceived;
        public delegate void ManifestReceivedHandler(uint appId, uint depotId, string depotName, ProtoManifest manifest);
        public static event DownloadCompleteHandler onDownloadCompleted;
        public delegate void DownloadCompleteHandler();

        private sealed class DepotDownloadInfo
        {
            public uint id { get; private set; }
            public string installDir { get; private set; }
            public string contentName { get; private set; }

            public ulong manifestId { get; private set; }
            public byte[] depotKey;

            public DepotDownloadInfo( uint depotid, ulong manifestId, string installDir, string contentName )
            {
                this.id = depotid;
                this.manifestId = manifestId;
                this.installDir = installDir;
                this.contentName = contentName;
            }
        }

        public static async Task DownloadApp(Steam3Session steam3, string installPath, uint appId, bool manifestOnly = false, params string[] fileList)
        {
            //Config.CellID = 0;
            Config.UsingFileList = fileList != null && fileList.Length > 0;
            if (Config.UsingFileList)
                Config.FilesToDownload = new List<string>(fileList);

            Config.InstallDirectory = installPath;
            Config.DownloadManifestOnly = manifestOnly;
            Config.MaxDownloads = 4;
            Config.MaxServers = 20;
            string branch = DEFAULT_BRANCH;

            string os = "windows";

            cdnPool = new CDNClientPool(steam3);
            //await DownloadAppAsync(steam3, appId, INVALID_DEPOT_ID, INVALID_MANIFEST_ID, branch, os, false).ConfigureAwait(false);
            try
            {
                await DownloadAppAsync(steam3, appId, INVALID_DEPOT_ID, INVALID_MANIFEST_ID, branch, os, false);
            }
            catch(Exception e) { DebugLog.WriteLine("ErrorContentDownloader", e.ToString()); }
            Shutdown();
        }

        static bool CreateDirectories(uint depotId, uint depotVersion, out string installDir)
        {
            installDir = null;
            try
            {
                if (string.IsNullOrWhiteSpace(ContentDownloader.Config.InstallDirectory))
                {
                    Directory.CreateDirectory(DEFAULT_DOWNLOAD_DIR);

                    string depotPath = Path.Combine(DEFAULT_DOWNLOAD_DIR, depotId.ToString());
                    Directory.CreateDirectory(depotPath);

                    installDir = Path.Combine(depotPath, depotVersion.ToString());
                    Directory.CreateDirectory(installDir);

                    Directory.CreateDirectory(Path.Combine(installDir, CONFIG_DIR));
                    Directory.CreateDirectory(Path.Combine(installDir, STAGING_DIR));
                }
                else
                {
                    Directory.CreateDirectory(ContentDownloader.Config.InstallDirectory);

                    installDir = ContentDownloader.Config.InstallDirectory;

                    Directory.CreateDirectory(Path.Combine(installDir, CONFIG_DIR));
                    Directory.CreateDirectory(Path.Combine(installDir, STAGING_DIR));
                }
            }
            catch
            {
                return false;
            }

            return true;
        }

        static bool TestIsFileIncluded( string filename )
        {
            if ( !Config.UsingFileList )
                return true;

            if (Config.FilesToDownload != null)
                foreach ( string fileListEntry in Config.FilesToDownload )
                {
                    if (Util.UriEquals(fileListEntry, filename))
                        return true;
                }

            if (Config.FilesToDownloadRegex != null)
                foreach ( Regex rgx in Config.FilesToDownloadRegex )
                {
                    Match m = rgx.Match( filename );

                    if ( m.Success )
                        return true;
                }

            return false;
        }

        static async Task<bool> AccountHasAccess( Steam3Session steam3, uint depotId )
        {
            if ( steam3 == null || steam3.steamUser.SteamID == null || ( steam3.Licenses == null && steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser ) )
                return false;

            IEnumerable<uint> licenseQuery;
            if ( steam3.steamUser.SteamID.AccountType == EAccountType.AnonUser )
            {
                licenseQuery = new List<uint>() { 17906 };
            }
            else
            {
                licenseQuery = steam3.Licenses.Select( x => x.PackageID );
            }

            await steam3.RequestPackageInfo(licenseQuery);

            foreach ( var license in licenseQuery )
            {
                SteamApps.PICSProductInfoCallback.PICSProductInfo package;
                if ( steam3.PackageInfo.TryGetValue( license, out package ) && package != null )
                {
                    if ( package.KeyValues[ "appids" ].Children.Any( child => child.AsUnsignedInteger() == depotId ) )
                        return true;

                    if ( package.KeyValues[ "depotids" ].Children.Any( child => child.AsUnsignedInteger() == depotId ) )
                        return true;
                }
            }

            return false;
        }

        internal static KeyValue GetSteam3AppSection( Steam3Session steam3, uint appId, EAppInfoSection section )
        {
            if ( steam3 == null || steam3.AppInfo == null )
            {
                return null;
            }

            SteamApps.PICSProductInfoCallback.PICSProductInfo app;
            if ( !steam3.AppInfo.TryGetValue( appId, out app ) || app == null )
            {
                return null;
            }

            KeyValue appinfo = app.KeyValues;
            string section_key;

            switch ( section )
            {
                case EAppInfoSection.Common:
                    section_key = "common";
                    break;
                case EAppInfoSection.Extended:
                    section_key = "extended";
                    break;
                case EAppInfoSection.Config:
                    section_key = "config";
                    break;
                case EAppInfoSection.Depots:
                    section_key = "depots";
                    break;
                default:
                    throw new NotImplementedException();
            }

            KeyValue section_kv = appinfo.Children.Where( c => c.Name == section_key ).FirstOrDefault();
            return section_kv;
        }

        static uint GetSteam3AppBuildNumber( Steam3Session steam3, uint appId, string branch )
        {
            if ( appId == INVALID_APP_ID )
                return 0;


            KeyValue depots = ContentDownloader.GetSteam3AppSection( steam3, appId, EAppInfoSection.Depots );
            KeyValue branches = depots[ "branches" ];
            KeyValue node = branches[ branch ];

            if ( node == KeyValue.Invalid )
                return 0;

            KeyValue buildid = node[ "buildid" ];

            if ( buildid == KeyValue.Invalid )
                return 0;

            return uint.Parse( buildid.Value );
        }

        static async Task<ulong> GetSteam3DepotManifest(Steam3Session steam3, uint depotId, uint appId, string branch)
        {
            KeyValue depots = GetSteam3AppSection(steam3, appId, EAppInfoSection.Depots);
            KeyValue depotChild = depots[ depotId.ToString() ];

            if ( depotChild == KeyValue.Invalid )
                return INVALID_MANIFEST_ID;

            // Shared depots can either provide manifests, or leave you relying on their parent app.
            // It seems that with the latter, "sharedinstall" will exist (and equals 2 in the one existance I know of).
            // Rather than relay on the unknown sharedinstall key, just look for manifests. Test cases: 111710, 346680.
            if ( depotChild[ "manifests" ] == KeyValue.Invalid && depotChild[ "depotfromapp" ] != KeyValue.Invalid )
            {
                uint otherAppId = depotChild["depotfromapp"].AsUnsignedInteger();
                if ( otherAppId == appId )
                {
                    // This shouldn't ever happen, but ya never know with Valve. Don't infinite loop.
                    DebugLog.WriteLine("ContentDownloader", "App " + appId + ", Depot " + depotId + " has depotfromapp of " + otherAppId + "!");
                    return INVALID_MANIFEST_ID;
                    //return INVALID_MANIFEST_ID;
                }

                await steam3.RequestAppInfo(otherAppId);
                return await GetSteam3DepotManifest(steam3, depotId, otherAppId, branch);
            }

            var manifests = depotChild["manifests"];
            var manifests_encrypted = depotChild["encryptedmanifests"];

            if ( manifests.Children.Count == 0 && manifests_encrypted.Children.Count == 0 )
                return INVALID_MANIFEST_ID;

            var node = manifests[ branch ];

            if ( branch != "Public" && node == KeyValue.Invalid )
            {
                var node_encrypted = manifests_encrypted[ branch ];
                if ( node_encrypted != KeyValue.Invalid )
                {
                    string password = Config.BetaPassword;
                    if ( password == null )
                    {
                        Config.BetaPassword = password = Console.ReadLine();
                    }

                    var encrypted_v1 = node_encrypted[ "encrypted_gid" ];
                    var encrypted_v2 = node_encrypted[ "encrypted_gid_2" ];

                    if ( encrypted_v1 != KeyValue.Invalid )
                    {
                        byte[] input = Util.DecodeHexString( encrypted_v1.Value );
                        byte[] manifest_bytes = CryptoHelper.VerifyAndDecryptPassword( input, password );

                        if ( manifest_bytes == null )
                        {
                            DebugLog.WriteLine("ContentDownloader", "Password was invalid for branch " + branch);
                            return INVALID_MANIFEST_ID;
                        }

                        return BitConverter.ToUInt64(manifest_bytes, 0);
                    }
                    else if ( encrypted_v2 != KeyValue.Invalid )
                    {
                        // Submit the password to Steam now to get encryption keys
                        await steam3.CheckAppBetaPassword(appId, Config.BetaPassword);

                        if (!steam3.AppBetaPasswords.ContainsKey(branch))
                        {
                            DebugLog.WriteLine("ContentDownloader", "Password was invalid for branch " + branch);
                            return INVALID_MANIFEST_ID;
                        }

                        byte[] input = Util.DecodeHexString( encrypted_v2.Value );
                        byte[] manifest_bytes = null;
                        try
                        {
                            manifest_bytes = CryptoHelper.SymmetricDecryptECB( input, steam3.AppBetaPasswords[ branch ] );
                        }
                        catch ( Exception e )
                        {
                            DebugLog.WriteLine("ContentDownloader", "Failed to decrypt branch " + branch + ": " + e.Message);
                            return INVALID_MANIFEST_ID;
                        }

                        return BitConverter.ToUInt64(manifest_bytes, 0);
                    }
                    else
                    {
                        DebugLog.WriteLine("ContentDownloader",  "Unhandled depot encryption for depotId " + depotId );
                        return INVALID_MANIFEST_ID;
                    }

                }

                return INVALID_MANIFEST_ID;
            }

            if ( node.Value == null )
                return INVALID_MANIFEST_ID;

            return ulong.Parse( node.Value );
        }

        static string GetAppOrDepotName( Steam3Session steam3, uint depotId, uint appId )
        {
            if ( depotId == INVALID_DEPOT_ID )
            {
                KeyValue info = GetSteam3AppSection( steam3, appId, EAppInfoSection.Common );

                if ( info == null )
                    return String.Empty;

                return info[ "name" ].AsString();
            }
            else
            {
                KeyValue depots = GetSteam3AppSection( steam3, appId, EAppInfoSection.Depots );

                if ( depots == null )
                    return String.Empty;

                KeyValue depotChild = depots[ depotId.ToString() ];

                if ( depotChild == null )
                    return String.Empty;

                return depotChild[ "name" ].AsString();
            }
        }

        public static void Shutdown()
        {
            if (cdnPool != null)
            {
                cdnPool.Shutdown();
                cdnPool = null;
            }
        }

        public static async Task DownloadPubfileAsync(Steam3Session steam3, ulong publishedFileId)
        {
            var details = await steam3.GetPubfileDetails(publishedFileId);

            if (details.hcontent_file > 0)
            {
                await DownloadAppAsync(steam3, details.consumer_appid, details.consumer_appid, details.hcontent_file, DEFAULT_BRANCH, null, true);
            }
            else
            {
                DebugLog.WriteLine("ContentDownloader", "Unable to locate manifest ID for published file " + publishedFileId);
            }
        }

        public static async Task DownloadAppAsync(Steam3Session steam3, uint appId, uint depotId, ulong manifestId, string branch, string os, bool isUgc)
        {
            if (steam3 != null)
                await steam3.RequestAppInfo(appId);

            bool hasAccess = await AccountHasAccess(steam3, appId);
            if (!hasAccess)
            {
                bool freeAppLicense = await steam3.RequestFreeAppLicense(appId);
                if (freeAppLicense)
                {
                    DebugLog.WriteLine("ContentDownloader",  "Obtained FreeOnDemand license for app " + appId );
                }
                else
                {
                    string contentName = GetAppOrDepotName(steam3, INVALID_DEPOT_ID, appId);
                    DebugLog.WriteLine("ContentDownloader", "App " + appId + " (" + contentName + ") is not available from this account.");
                    return;
                }
            }

            var depotIDs = new List<uint>();
            KeyValue depots = GetSteam3AppSection( steam3, appId, EAppInfoSection.Depots );

            if (isUgc)
            {
                var workshopDepot = depots["workshopdepot"].AsUnsignedInteger();
                if (workshopDepot != 0)
                    depotId = workshopDepot;

                depotIDs.Add(depotId);
            }
            else
            {
                DebugLog.WriteLine("ContentDownloader", "Using app branch: '" + branch + "'.");

                if (depots != null)
                {
                    foreach (var depotSection in depots.Children)
                    {
                        uint id = INVALID_DEPOT_ID;
                        if (depotSection.Children.Count == 0)
                            continue;

                        if (!uint.TryParse(depotSection.Name, out id))
                            continue;

                        if (depotId != INVALID_DEPOT_ID && id != depotId)
                            continue;

                        if (depotId == INVALID_DEPOT_ID && !Config.DownloadAllPlatforms)
                        {
                            var depotConfig = depotSection[ "config" ];
                            if (depotConfig != KeyValue.Invalid && depotConfig[ "oslist" ] != KeyValue.Invalid && !string.IsNullOrWhiteSpace(depotConfig["oslist"].Value))
                            {
                                var oslist = depotConfig["oslist"].Value.Split(',');
                                if (Array.IndexOf(oslist, os ?? Util.GetSteamOS()) == -1)
                                    continue;
                            }
                        }

                        depotIDs.Add(id);
                    }
                }
                if (depotIDs == null || (depotIDs.Count == 0 && depotId == INVALID_DEPOT_ID))
                {
                    DebugLog.WriteLine("ContentDownloader", "Couldn't find any depots to download for app " + appId);
                    return;
                }
                else if (depotIDs.Count == 0)
                {
                    DebugLog.WriteLine("ContentDownloader", "Depot " + depotId + " not listed for app " + appId);
                    return;
                }
            }

            var infos = new List<DepotDownloadInfo>();

            foreach (var depot in depotIDs)
            {
                var info = await GetDepotInfo(steam3, depot, appId, manifestId, branch);
                if (info != null)
                {
                    infos.Add(info);
                }
            }

            try
            {
                IsDownloading = true;
                await DownloadSteam3Async(appId, infos);
            }
            catch (OperationCanceledException)
            {
                DebugLog.WriteLine("ContentDownloader", "App " + appId + " was not completely downloaded.");
            }
            finally
            {
                DebugLog.WriteLine("ContentDownloader", "Download completed");
                IsDownloading = false;
                onDownloadCompleted?.Invoke();
            }
        }

        static async Task<DepotDownloadInfo> GetDepotInfo(Steam3Session steam3, uint depotId, uint appId, ulong manifestId, string branch)
        {
            if (steam3 != null && appId != INVALID_APP_ID)
                await steam3.RequestAppInfo(appId);

            string contentName = GetAppOrDepotName( steam3, depotId, appId );

            bool hasAccess = await AccountHasAccess(steam3, depotId);
            if (!hasAccess)
            {
                DebugLog.WriteLine("ContentDownloader", "Depot " + depotId + " (" + contentName + ") is not available from this account.");

                return null;
            }

            // Skip requesting an app ticket
            steam3.AppTickets[ depotId ] = null;

            if (manifestId == INVALID_MANIFEST_ID)
            {
                manifestId = await GetSteam3DepotManifest(steam3, depotId, appId, branch);
                if (manifestId == INVALID_MANIFEST_ID && branch != "public")
                {
                    DebugLog.WriteLine("ContentDownloader", "Warning: Depot " + depotId + " does not have branch named \"" + branch + "\". Trying public branch.");
                    branch = "public";
                    manifestId = await GetSteam3DepotManifest(steam3, depotId, appId, branch);
                }

                if (manifestId == INVALID_MANIFEST_ID)
                {
                    DebugLog.WriteLine("ContentDownloader", "Depot " + depotId + " (" + contentName + ") missing public subsection or manifest section.");
                    return null;
                }
            }

            uint uVersion = GetSteam3AppBuildNumber( steam3, appId, branch );

            string installDir;
            if (!CreateDirectories(depotId, uVersion, out installDir))
            {
                DebugLog.WriteLine("ContentDownloader", "Error: Unable to create install directories!");
                return null;
            }

            await steam3.RequestDepotKey(depotId, appId);
            if (!steam3.DepotKeys.ContainsKey(depotId))
            {
                DebugLog.WriteLine("ContentDownloader", "No valid depot key for " + depotId + ", unable to download.");
                return null;
            }

            byte[] depotKey = steam3.DepotKeys[ depotId ];

            var info = new DepotDownloadInfo(depotId, manifestId, installDir, contentName);
            info.depotKey = depotKey;
            return info;
        }

        private class ChunkMatch
        {
            public ChunkMatch(ProtoManifest.ChunkData oldChunk, ProtoManifest.ChunkData newChunk)
            {
                OldChunk = oldChunk;
                NewChunk = newChunk;
            }
            public ProtoManifest.ChunkData OldChunk { get; private set; }
            public ProtoManifest.ChunkData NewChunk { get; private set; }
        }

        private static async Task DownloadSteam3Async(uint appId, List<DepotDownloadInfo> depots)
        {
            ulong TotalBytesCompressed = 0;
            ulong TotalBytesUncompressed = 0;

            foreach ( var depot in depots )
            {
                ulong DepotBytesCompressed = 0;
                ulong DepotBytesUncompressed = 0;

                DebugLog.WriteLine("ContentDownloader", "Downloading depot " + depot.id + " - " + depot.contentName);

                CancellationTokenSource cts = new CancellationTokenSource();
                cdnPool.ExhaustedToken = cts;

                ProtoManifest oldProtoManifest = null;
                ProtoManifest downloadManifest = null;
                string configDir = Path.Combine( depot.installDir, CONFIG_DIR );

                ulong lastManifestId = INVALID_MANIFEST_ID;
                ConfigStore.TheConfig.LastManifests.TryGetValue( depot.id, out lastManifestId );

                // In case we have an early exit, this will force equiv of verifyall next run.
                ConfigStore.TheConfig.LastManifests[ depot.id ] = INVALID_MANIFEST_ID;
                ConfigStore.Save();

                if ( lastManifestId != INVALID_MANIFEST_ID )
                {
                    var oldManifestFileName = Path.Combine( configDir, string.Format( "{0}.bin", lastManifestId ) );
                    DebugLog.WriteLine(DEBUG_NAME_FILES, "Checking if " + oldManifestFileName + " exists");
                    if (File.Exists(oldManifestFileName))
                    {
                        DebugLog.WriteLine(DEBUG_NAME_FILES, oldManifestFileName + " exists, reading!");
                        oldProtoManifest = ProtoManifest.LoadFromFile(oldManifestFileName);
                    }
                }

                if ( lastManifestId == depot.manifestId && oldProtoManifest != null )
                {
                    downloadManifest = oldProtoManifest;
                    DebugLog.WriteLine("ContentDownloader", "Already have manifest " + depot.manifestId + " for depot " + depot.id + ".");
                }
                else
                {
                    var newManifestFileName = Path.Combine( configDir, string.Format( "{0}.bin", depot.manifestId ) );
                    if ( newManifestFileName != null )
                    {
                        downloadManifest = ProtoManifest.LoadFromFile( newManifestFileName );
                    }

                    if ( downloadManifest != null )
                    {
                        DebugLog.WriteLine("ContentDownloader", "Already have manifest " + depot.manifestId + " for depot " + depot.id + ".");
                    }
                    else
                    {
                        DebugLog.WriteLine("ContentDownloader",  "Downloading depot manifest..." );

                        DepotManifest depotManifest = null;

                        while ( depotManifest == null )
                        {
                            CDNClient client = null;
                            try
                            {
                                client = await cdnPool.GetConnectionForDepotAsync(appId, depot.id, depot.depotKey, CancellationToken.None).ConfigureAwait(false);
                                //client = await cdnPool.GetConnectionForDepotAsync(appId, depot.id, depot.depotKey, CancellationToken.None);

                                depotManifest = await client.DownloadManifestAsync(depot.id, depot.manifestId).ConfigureAwait(false);
                                //depotManifest = await client.DownloadManifestAsync(depot.id, depot.manifestId);

                                cdnPool.ReturnConnection(client);
                            }
                            catch (WebException e)
                            {
                                cdnPool.ReturnBrokenConnection(client);

                                if (e.Status == WebExceptionStatus.ProtocolError)
                                {
                                    var response = e.Response as HttpWebResponse;
                                    if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                                    {
                                        DebugLog.WriteLine("ContentDownloader", "Encountered 401 for depot manifest " + depot.id + " " + depot.manifestId + ". Aborting.");
                                        break;
                                    }
                                    else
                                    {
                                        DebugLog.WriteLine("ContentDownloader", "Encountered error downloading depot manifest " + depot.id + " " + depot.manifestId + ": " + response.StatusCode);
                                    }
                                }
                                else
                                {
                                    DebugLog.WriteLine("ContentDownloader", "Encountered error downloading manifest for depot " + depot.id + " " + depot.manifestId + ": " + e.Status);
                                }
                            }
                            catch (Exception e)
                            {
                                cdnPool.ReturnBrokenConnection(client);
                                DebugLog.WriteLine("ContentDownloader", "Encountered error downloading manifest for depot " + depot.id + " " + depot.manifestId + ": " + e.Message );
                            }
                        }

                        if ( depotManifest == null )
                        {
                            DebugLog.WriteLine("ContentDownloader", "\nUnable to download manifest " + depot.manifestId + " for depot " + depot.id );
                            return;
                        }

                        downloadManifest = new ProtoManifest( depotManifest, depot.manifestId );
                        downloadManifest.SaveToFile( newManifestFileName );

                        DebugLog.WriteLine("ContentDownloader", "Done!");
                    }
                }

                downloadManifest.Files.Sort( ( x, y ) => { return x.FileName.CompareTo( y.FileName ); } );
                if (downloadManifest != null)
                    onManifestReceived?.Invoke(appId, depot.id, depot.contentName, downloadManifest);

                if ( Config.DownloadManifestOnly )
                    continue;

                complete_download_size = 0;
                size_downloaded = 0;
                string stagingDir = Path.Combine( depot.installDir, STAGING_DIR );

                var filesAfterExclusions = downloadManifest.Files.AsParallel().Where( f => TestIsFileIncluded( f.FileName ) ).ToList();

                // Pre-process
                filesAfterExclusions.ForEach( file =>
                {
                    var fileFinalPath = Path.Combine( depot.installDir, file.FileName );
                    var fileStagingPath = Path.Combine( stagingDir, file.FileName );

                    if ( file.Flags.HasFlag( EDepotFileFlag.Directory ) )
                    {
                        Directory.CreateDirectory( fileFinalPath );
                        Directory.CreateDirectory( fileStagingPath );
                    }
                    else
                    {
                        // Some manifests don't explicitly include all necessary directories
                        Directory.CreateDirectory( Path.GetDirectoryName( fileFinalPath ) );
                        Directory.CreateDirectory( Path.GetDirectoryName( fileStagingPath ) );

                        complete_download_size += file.TotalSize;
                    }
                } );

                var semaphore = new SemaphoreSlim( Config.MaxDownloads );
                var files = filesAfterExclusions.Where( f => !f.Flags.HasFlag( EDepotFileFlag.Directory ) ).ToArray();
                var tasks = new Task[ files.Length ];
                for ( var i = 0; i < files.Length; i++ )
                {
                    var file = files[ i ];
                    var task = Task.Run( async () =>
                    {
                        cts.Token.ThrowIfCancellationRequested();
                        
                        try
                        {
                            await semaphore.WaitAsync().ConfigureAwait( false );
                            //await semaphore.WaitAsync();
                            cts.Token.ThrowIfCancellationRequested();

                            string fileFinalPath = Path.Combine( depot.installDir, file.FileName );
                            string fileStagingPath = Path.Combine( stagingDir, file.FileName );

                            // This may still exist if the previous run exited before cleanup
                            DebugLog.WriteLine(DEBUG_NAME_FILES, "Checking if " + fileStagingPath + " exists");
                            if ( File.Exists( fileStagingPath ) )
                            {
                                DebugLog.WriteLine(DEBUG_NAME_FILES, fileStagingPath + " exists, deleting!");
                                File.Delete( fileStagingPath );
                            }

                            List<ProtoManifest.ChunkData> neededChunks;
                            FileInfo fi = new FileInfo( fileFinalPath );
                            DebugLog.WriteLine(DEBUG_NAME_FILES, "Checking if " + fileFinalPath + " exists");
                            if ( !fi.Exists )
                            {
                                // create new file. need all chunks
                                DebugLog.WriteLine(DEBUG_NAME_FILES, fileFinalPath + " does not exist, creating!");
                                using (FileStream fs = File.Create(fileFinalPath))
                                {
                                    fs.SetLength((long)file.TotalSize);
                                    neededChunks = new List<ProtoManifest.ChunkData>(file.Chunks);
                                }
                            }
                            else
                            {
                                // open existing
                                ProtoManifest.FileData oldManifestFile = null;
                                if ( oldProtoManifest != null )
                                {
                                    oldManifestFile = oldProtoManifest.Files.SingleOrDefault( f => f.FileName == file.FileName );
                                }

                                if ( oldManifestFile != null )
                                {
                                    neededChunks = new List<ProtoManifest.ChunkData>();

                                    if ( Config.VerifyAll || !oldManifestFile.FileHash.SequenceEqual( file.FileHash ) )
                                    {
                                        // we have a version of this file, but it doesn't fully match what we want

                                        var matchingChunks = new List<ChunkMatch>();

                                        foreach ( var chunk in file.Chunks )
                                        {
                                            var oldChunk = oldManifestFile.Chunks.FirstOrDefault( c => c.ChunkID.SequenceEqual( chunk.ChunkID ) );
                                            if ( oldChunk != null )
                                            {
                                                matchingChunks.Add( new ChunkMatch( oldChunk, chunk ) );
                                            }
                                            else
                                            {
                                                neededChunks.Add( chunk );
                                            }
                                        }

                                        DebugLog.WriteLine(DEBUG_NAME_FILES, "Moving file " + fileFinalPath + " to " + fileStagingPath);
                                        File.Move( fileFinalPath, fileStagingPath );

                                        DebugLog.WriteLine(DEBUG_NAME_FILES, "Creating file " + fileFinalPath);
                                        using (FileStream fs = File.Open(fileFinalPath, FileMode.Create))
                                        {
                                            fs.SetLength((long)file.TotalSize);

                                            DebugLog.WriteLine(DEBUG_NAME_FILES, "Opening file " + fileStagingPath);
                                            using (var fsOld = File.Open(fileStagingPath, FileMode.Open))
                                            {
                                                foreach (var match in matchingChunks)
                                                {
                                                    fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

                                                    byte[] tmp = new byte[match.OldChunk.UncompressedLength];
                                                    fsOld.Read(tmp, 0, tmp.Length);

                                                    byte[] adler = Util.AdlerHash(tmp);
                                                    if (!adler.SequenceEqual(match.OldChunk.Checksum))
                                                    {
                                                        neededChunks.Add(match.NewChunk);
                                                    }
                                                    else
                                                    {
                                                        fs.Seek((long)match.NewChunk.Offset, SeekOrigin.Begin);
                                                        fs.Write(tmp, 0, tmp.Length);
                                                    }
                                                }
                                            }
                                        }
                                        DebugLog.WriteLine(DEBUG_NAME_FILES, "Deleting file " + fileStagingPath);
                                        File.Delete( fileStagingPath );
                                    }
                                }
                                else
                                {
                                    // No old manifest or file not in old manifest. We must validate.

                                    DebugLog.WriteLine(DEBUG_NAME_FILES, "Opening file " + fileFinalPath);
                                    using (FileStream fs = File.Open(fileFinalPath, FileMode.Open))
                                    {
                                        if ((ulong)fi.Length != file.TotalSize)
                                        {
                                            fs.SetLength((long)file.TotalSize);
                                        }

                                        neededChunks = Util.ValidateSteam3FileChecksums(fs, file.Chunks.OrderBy(x => x.Offset).ToArray());
                                    }
                                }

                                if (neededChunks.Count() == 0)
                                {
                                    size_downloaded += file.TotalSize;
                                    size_downloaded += file.TotalSize;
                                    DebugLog.WriteLine("ContentDownloader", DownloadPercent * 100.0f + "% " + fileFinalPath);
                                    return;
                                }
                                else
                                {
                                    size_downloaded += ( file.TotalSize - ( ulong )neededChunks.Select( x => ( long )x.UncompressedLength ).Sum() );
                                }
                            }

                            DebugLog.WriteLine(DEBUG_NAME_FILES, "Opening file " + fileFinalPath);
                            using (FileStream fs = File.Open(fileFinalPath, FileMode.Open))
                            {
                                foreach (var chunk in neededChunks)
                                {
                                    if (cts.IsCancellationRequested) break;

                                    string chunkID = Util.EncodeHexString(chunk.ChunkID);
                                    CDNClient.DepotChunk chunkData = null;

                                    while (!cts.IsCancellationRequested)
                                    {
                                        CDNClient client;
                                        try
                                        {
                                            client = await cdnPool.GetConnectionForDepotAsync(appId, depot.id, depot.depotKey, cts.Token).ConfigureAwait(false);
                                            //client = await cdnPool.GetConnectionForDepotAsync(appId, depot.id, depot.depotKey, cts.Token);
                                        }
                                        catch (OperationCanceledException)
                                        {
                                            break;
                                        }

                                        DepotManifest.ChunkData data = new DepotManifest.ChunkData();
                                        data.ChunkID = chunk.ChunkID;
                                        data.Checksum = chunk.Checksum;
                                        data.Offset = chunk.Offset;
                                        data.CompressedLength = chunk.CompressedLength;
                                        data.UncompressedLength = chunk.UncompressedLength;

                                        try
                                        {
                                            chunkData = await client.DownloadDepotChunkAsStreamAsync(depot.id, data).ConfigureAwait(false);
                                            //chunkData = await client.DownloadDepotChunkAsync(depot.id, data);
                                            cdnPool.ReturnConnection(client);
                                            break;
                                        }
                                        catch (WebException e)
                                        {
                                            cdnPool.ReturnBrokenConnection(client);

                                            if (e.Status == WebExceptionStatus.ProtocolError)
                                            {
                                                var response = e.Response as HttpWebResponse;
                                                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                                                {
                                                    DebugLog.WriteLine("ContentDownloader", "Encountered 401 for chunk " + chunkID + ". Aborting.");
                                                    cts.Cancel();
                                                    break;
                                                }
                                                else
                                                {
                                                    DebugLog.WriteLine("ContentDownloader", "Encountered error downloading chunk " + chunkID + ": " + response.StatusCode);
                                                }
                                            }
                                            else
                                            {
                                                DebugLog.WriteLine("ContentDownloader", "Encountered error downloading chunk " + chunkID + ": " + e.Status);
                                            }
                                        }
                                        catch (Exception e)
                                        {
                                            cdnPool.ReturnBrokenConnection(client);
                                            DebugLog.WriteLine("ContentDownloader", "Encountered unexpected error downloading chunk " + chunkID + ": " + e.Message);
                                        }
                                    }

                                    if (chunkData == null)
                                    {
                                        DebugLog.WriteLine("ContentDownloader", "Failed to find any server with chunk " + chunkID + " for depot " + depot.id + ". Aborting.");
                                        cts.Cancel();
                                        return;
                                    }

                                    TotalBytesCompressed += chunk.CompressedLength;
                                    DepotBytesCompressed += chunk.CompressedLength;
                                    TotalBytesUncompressed += chunk.UncompressedLength;
                                    DepotBytesUncompressed += chunk.UncompressedLength;

                                    using (chunkData.DataStream)
                                    {

                                        fs.Seek((long)chunk.Offset, SeekOrigin.Begin);
                                        chunkData.DataStream.CopyTo(fs);
                                        //fs.Write(chunkData.Data, 0, chunkData.Data.Length);
                                    }

                                    size_downloaded += chunk.UncompressedLength;
                                }
                            }
                            DebugLog.WriteLine("ContentDownloader", DownloadPercent * 100.0f + "% " + fileFinalPath );
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    } );

                    tasks[ i ] = task;
                }

                //await Task.WhenAll(tasks).ConfigureAwait(false);
                await Task.WhenAll(tasks);

                ConfigStore.TheConfig.LastManifests[ depot.id ] = depot.manifestId;
                ConfigStore.Save();

                DebugLog.WriteLine("ContentDownloader", "Depot " + depot.id + " - Downloaded " + DepotBytesCompressed + " bytes (" + DepotBytesUncompressed + " bytes uncompressed)");
            }

            DebugLog.WriteLine("ContentDownloader", "Total downloaded: " + TotalBytesCompressed + " bytes (" + TotalBytesUncompressed + " bytes uncompressed) from " + depots.Count + " depots");
        }
    }
}
