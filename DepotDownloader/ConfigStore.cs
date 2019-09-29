﻿using System;
using System.Collections.Generic;
using ProtoBuf;
using System.IO;
using Ionic.Zlib;

namespace DepotDownloader
{
    [ProtoContract]
    public class ConfigStore
    {
        [ProtoMember(1)]
        public Dictionary<uint, ulong> LastManifests { get; private set; }

        [ProtoMember(3, IsRequired=false)]
        public Dictionary<string, byte[]> SentryData { get; private set; }

        [ProtoMember(4, IsRequired = false)]
        public System.Collections.Concurrent.ConcurrentDictionary<string, int> ContentServerPenalty { get; private set; }

        [ProtoMember(5, IsRequired = false)]
        public Dictionary<string, string> LoginKeys { get; private set; }

        string FileName = null;

        public ConfigStore()
        {
            LastManifests = new Dictionary<uint, ulong>();
            SentryData = new Dictionary<string, byte[]>();
            ContentServerPenalty = new System.Collections.Concurrent.ConcurrentDictionary<string, int>();
            LoginKeys = new Dictionary<string, string>();
        }

        static bool Loaded
        {
            get { return TheConfig != null; }
        }

        public static ConfigStore TheConfig = null;

        public static void LoadFromFile(string filename)
        {
            if (Loaded)
                throw new Exception("Config already loaded");

            if (File.Exists(filename))
            {
                using (FileStream fs = File.Open(filename, FileMode.Open))
                using (DeflateStream ds = new DeflateStream(fs, CompressionMode.Decompress))
                {
                    ProtoBuf.Meta.TypeModel model = (ProtoBuf.Meta.TypeModel)Activator.CreateInstance(Type.GetType("MyProtoModel, MyProtoModel"));
                    TheConfig = (ConfigStore)model.Deserialize(ds, null, typeof(ConfigStore));
                    //TheConfig = ProtoBuf.Serializer.Deserialize<ConfigStore>(ds);
                }
            }
            else
            {
                TheConfig = new ConfigStore();
            }

            TheConfig.FileName = filename;
        }

        public static void Save()
        {
            if (!Loaded)
                throw new Exception("Saved config before loading");

            using (FileStream fs = File.Open(TheConfig.FileName, FileMode.Create))
            using (DeflateStream ds = new DeflateStream(fs, CompressionMode.Compress))
            {
                ProtoBuf.Meta.TypeModel model = (ProtoBuf.Meta.TypeModel)Activator.CreateInstance(Type.GetType("MyProtoModel, MyProtoModel"));
                model.Serialize(ds, TheConfig);
                //ProtoBuf.Serializer.Serialize<ConfigStore>(ds, TheConfig);
            }
        }
    }
}
