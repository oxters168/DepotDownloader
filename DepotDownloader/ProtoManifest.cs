using System;
using System.Collections.Generic;
using System.IO;
using Ionic.Zlib;

using ProtoBuf;
using SteamKit2;

namespace DepotDownloader
{
    [ProtoContract()]
    public class ProtoManifest
    {
        // Proto ctor
        public ProtoManifest()
        {
            Files = new List<FileData>();
        }

        public ProtoManifest(DepotManifest sourceManifest, ulong id) : this()
        {
            sourceManifest.Files.ForEach(f => Files.Add(new FileData(f)));
            ID = id;
        }

        [ProtoContract()]
        public class FileData : IEquatable<FileData>
        {
            // Proto ctor
            public FileData()
            {
                Chunks = new List<ChunkData>();
            }

            public FileData(DepotManifest.FileData sourceData) : this()
            {
                FileName = sourceData.FileName;
                sourceData.Chunks.ForEach(c => Chunks.Add(new ChunkData(c)));
                Flags = sourceData.Flags;
                TotalSize = sourceData.TotalSize;
                FileHash = sourceData.FileHash;
            }

            [ProtoMember(1)]
            public string FileName { get; set; }

            /// <summary>
            /// Gets the chunks that this file is composed of.
            /// </summary>
            [ProtoMember(2)]
            public List<ChunkData> Chunks { get; set; }

            /// <summary>
            /// Gets the file flags
            /// </summary>
            [ProtoMember(3)]
            public EDepotFileFlag Flags { get; set; }

            /// <summary>
            /// Gets the total size of this file.
            /// </summary>
            [ProtoMember(4)]
            public ulong TotalSize { get; set; }

            /// <summary>
            /// Gets the hash of this file.
            /// </summary>
            [ProtoMember(5)]
            public byte[] FileHash { get; set; }

            public override bool Equals(object obj)
            {
                bool equal = true;
                if (obj is FileData)
                    equal = Equals((FileData)obj);
                else
                    equal = false;

                return equal;
            }
            public override int GetHashCode()
            {
                return FileName.GetHashCode();
            }

            public bool Equals(FileData other)
            {
                return Util.UriEquals(FileName, other.FileName);
            }
        }

        [ProtoContract(SkipConstructor = true)]
        public class ChunkData
        {
            public ChunkData(DepotManifest.ChunkData sourceChunk)
            {
                ChunkID = sourceChunk.ChunkID;
                Checksum = sourceChunk.Checksum;
                Offset = sourceChunk.Offset;
                CompressedLength = sourceChunk.CompressedLength;
                UncompressedLength = sourceChunk.UncompressedLength;
            }

            /// <summary>
            /// Gets the SHA-1 hash chunk id.
            /// </summary>
            [ProtoMember(1)]
            public byte[] ChunkID { get; set; }

            /// <summary>
            /// Gets the expected Adler32 checksum of this chunk.
            /// </summary>
            [ProtoMember(2)]
            public byte[] Checksum { get; set; }

            /// <summary>
            /// Gets the chunk offset.
            /// </summary>
            [ProtoMember(3)]
            public ulong Offset { get; set; }

            /// <summary>
            /// Gets the compressed length of this chunk.
            /// </summary>
            [ProtoMember(4)]
            public uint CompressedLength { get; set; }

            /// <summary>
            /// Gets the decompressed length of this chunk.
            /// </summary>
            [ProtoMember(5)]
            public uint UncompressedLength { get; set; }
        }

        [ProtoMember(1)]
        public List<FileData> Files { get; set; }

        [ProtoMember(2)]
        public ulong ID { get; set; }

        public static ProtoManifest LoadFromFile(string filename)
        {
            if (!File.Exists(filename))
                return null;

            using (FileStream fs = File.Open(filename, FileMode.Open))
            using (DeflateStream ds = new DeflateStream(fs, CompressionMode.Decompress))
            {
                ProtoBuf.Meta.TypeModel model = (ProtoBuf.Meta.TypeModel)Activator.CreateInstance(Type.GetType("MyProtoModel, MyProtoModel"));
                return (ProtoManifest)model.Deserialize(ds, null, typeof(ProtoManifest));
                //return ProtoBuf.Serializer.Deserialize<ProtoManifest>(ds);
            }
        }

        public void SaveToFile(string filename)
        {
            using (FileStream fs = File.Open(filename, FileMode.Create))
            using (DeflateStream ds = new DeflateStream(fs, CompressionMode.Compress))
            {
                ProtoBuf.Meta.TypeModel model = (ProtoBuf.Meta.TypeModel)Activator.CreateInstance(Type.GetType("MyProtoModel, MyProtoModel"));
                model.Serialize(ds, this);
                //ProtoBuf.Serializer.Serialize<ProtoManifest>(ds, this);
            }
        }
    }
}
