﻿using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DepotDownloader
{
    public class DownloadConfig
    {
        public int CellID { get; set; }
        public bool DownloadAllPlatforms { get; set; }
        public bool DownloadManifestOnly { get; set; }
        public string InstallDirectory { get; set; }

        public bool UsingFileList { get; set; }
        public List<string> FilesToDownload { get; set; }
        public List<Regex> FilesToDownloadRegex { get; set; }

        //public bool UsingExclusionList { get; set; }

        public string BetaPassword { get; set; }

        public bool VerifyAll { get; set; }

        public int MaxServers { get; set; }
        public int MaxDownloads { get; set; }

        //public string SuppliedPassword { get; set; }
        //public bool RememberPassword { get; set; }
    }
}
