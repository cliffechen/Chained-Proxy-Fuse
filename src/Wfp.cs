using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;

namespace ChainedProxyFuse
{
    // ---------- WFP：总闸 + 放行名单（UU 远程等） ----------
    // 为什么不用 Windows 防火墙规则做总闸：sing-box 自己有一个最高优先级（0xFFFF）的子层，
    // 给所有走虚拟网卡的连接一个“软放行”，之后我们的“硬放行”就盖不过防火墙的拦截规则了。
    // 所以总闸和放行名单都放进我们自己的子层：同一子层里权重高的“放行”先命中，名单里的程序不受总闸影响；
    // 名单里的程序用“硬放行”，在真实网卡上还能盖过防火墙里的门禁规则。
    // 规则都是持久的：重启、本工具崩溃都还在，和防火墙规则一样。
    static class Wfp
    {
        [StructLayout(LayoutKind.Explicit, Size = 72)]
        struct Session { [FieldOffset(32)] public uint flags; }

        [StructLayout(LayoutKind.Explicit, Size = 72)]
        struct SubLayer
        {
            [FieldOffset(0)] public Guid key;
            [FieldOffset(16)] public IntPtr name;
            [FieldOffset(32)] public uint flags;
            [FieldOffset(64)] public ushort weight;
        }

        [StructLayout(LayoutKind.Explicit, Size = 40)]
        struct Cond
        {
            [FieldOffset(0)] public Guid field;
            [FieldOffset(16)] public uint match;
            [FieldOffset(24)] public uint type;
            [FieldOffset(32)] public IntPtr value;
        }

        [StructLayout(LayoutKind.Explicit, Size = 32)]
        struct Range
        {
            [FieldOffset(0)] public uint lowType;
            [FieldOffset(8)] public long low;      // UINT32 直接存值；16 字节数组存指针
            [FieldOffset(16)] public uint highType;
            [FieldOffset(24)] public long high;
        }

        [StructLayout(LayoutKind.Explicit, Size = 200)]
        struct Filter
        {
            [FieldOffset(0)] public Guid key;
            [FieldOffset(16)] public IntPtr name;
            [FieldOffset(32)] public uint flags;
            [FieldOffset(64)] public Guid layer;
            [FieldOffset(80)] public Guid subLayer;
            [FieldOffset(96)] public uint weightType;
            [FieldOffset(104)] public byte weight;
            [FieldOffset(112)] public uint numConds;
            [FieldOffset(120)] public IntPtr conds;
            [FieldOffset(128)] public uint actionType;
        }

        [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineOpen0(string server, uint authn, IntPtr ident, ref Session s, out IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine, ref SubLayer s, IntPtr sd);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter f, IntPtr sd, out ulong id);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
        [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr p);
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file, out IntPtr blob);

        static readonly Guid LayerV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"); // FWPM_LAYER_ALE_AUTH_CONNECT_V4
        static readonly Guid LayerV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"); // FWPM_LAYER_ALE_AUTH_CONNECT_V6
        static readonly Guid CondAppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");      // FWPM_CONDITION_ALE_APP_ID
        static readonly Guid CondRemoteAddr = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045"); // FWPM_CONDITION_IP_REMOTE_ADDRESS
        static readonly Guid SubKey = new Guid("6f1a3c52-9b0e-4d7a-8e21-c0ffee000100");
        const int KindBypass = 1, KindTrip = 2, MaxPerKind = 64;
        const uint FlagPersistent = 1, FlagClearActionRight = 8;
        const uint ActionBlock = 0x1001, ActionPermit = 0x1002;
        const uint TypeUint8 = 1, TypeUint32 = 3, TypeBytes16 = 11, TypeBlob = 12, TypeRange = 0x102;
        const uint MatchEqual = 0, MatchRange = 5;
        const uint ErrAlreadyExists = 0x80320009;

        // 固定的过滤器 key，这样不用记 ID 也能精确删除
        static Guid Key(int kind, int i) { return new Guid(0x6f1a3c52, 0x9b0e, 0x4d7a, 0x8e, 0x21, 0xc0, 0xff, 0xee, (byte)kind, 0, (byte)i); }

        static void Check(uint r, string what) { if (r != 0) throw new Exception(what + " 失败 0x" + r.ToString("X8")); }

        // 打开引擎、开事务，全部成功才提交
        static T Txn<T>(Func<IntPtr, T> body)
        {
            var s = new Session();
            IntPtr eng;
            Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, ref s, out eng), "FwpmEngineOpen");
            try
            {
                Check(FwpmTransactionBegin0(eng, 0), "FwpmTransactionBegin");
                try { var r = body(eng); Check(FwpmTransactionCommit0(eng), "FwpmTransactionCommit"); return r; }
                catch { FwpmTransactionAbort0(eng); throw; }
            }
            finally { FwpmEngineClose0(eng); }
        }

        // 刷新放行名单和总闸（总闸开关由 trip 决定，白名单变了也要重建）
        public static int Apply(IEnumerable<string> bypassExes, bool trip, IEnumerable<string> allowIps)
        {
            return Txn(eng =>
            {
                EnsureSubLayer(eng);
                int n = SetBypass(eng, bypassExes);
                SetTrip(eng, trip, allowIps);
                return n;
            });
        }

        public static void SetTrip(bool on, IEnumerable<string> allowIps)
        {
            Txn(eng => { EnsureSubLayer(eng); SetTrip(eng, on, allowIps); return 0; });
        }

        public static bool TripOn()
        {
            try
            {
                return Txn(eng =>
                {
                    var k = Key(KindTrip, 0); IntPtr f;
                    if (FwpmFilterGetByKey0(eng, ref k, out f) != 0) return false;
                    FwpmFreeMemory0(ref f); return true;
                });
            }
            catch { return false; }
        }

        // 撤掉全部 WFP 对象
        public static void RemoveAll()
        {
            Txn(eng =>
            {
                RemoveKind(eng, KindBypass); RemoveKind(eng, KindTrip);
                var k = SubKey; FwpmSubLayerDeleteByKey0(eng, ref k);
                return 0;
            });
        }

        static void EnsureSubLayer(IntPtr eng)
        {
            var name = Marshal.StringToHGlobalUni("ChainedProxyFuse");
            try
            {
                // sing-box 占了 0xFFFF；我们紧随其后，排在 Windows 防火墙之前
                var sl = new SubLayer { key = SubKey, name = name, flags = FlagPersistent, weight = 0xFFFE };
                uint r = FwpmSubLayerAdd0(eng, ref sl, IntPtr.Zero);
                if (r != ErrAlreadyExists) Check(r, "FwpmSubLayerAdd");
            }
            finally { Marshal.FreeHGlobal(name); }
        }

        static void RemoveKind(IntPtr eng, int kind)
        {
            for (int i = 0; i < MaxPerKind; i++) { var k = Key(kind, i); FwpmFilterDeleteByKey0(eng, ref k); }
        }

        // 放行名单：每个程序 IPv4/IPv6 各一条硬放行（权重 15，高于总闸）
        static int SetBypass(IntPtr eng, IEnumerable<string> exes)
        {
            RemoveKind(eng, KindBypass);
            int i = 0;
            foreach (var exe in exes)
            {
                if (i + 2 > MaxPerKind) break;
                IntPtr blob;
                if (FwpmGetAppIdFromFileName0(exe, out blob) != 0) continue;
                try
                {
                    var c = new[] { new Cond { field = CondAppId, match = MatchEqual, type = TypeBlob, value = blob } };
                    string name = "CPF-Bypass " + Path.GetFileName(exe);
                    AddFilter(eng, Key(KindBypass, i++), name, LayerV4, c, ActionPermit, 15, FlagPersistent | FlagClearActionRight);
                    AddFilter(eng, Key(KindBypass, i++), name, LayerV6, c, ActionPermit, 15, FlagPersistent | FlagClearActionRight);
                }
                finally { FwpmFreeMemory0(ref blob); }
            }
            return i / 2;
        }

        // 总闸：所有网卡上，除局域网/白名单外的地址一律拦截（权重 1）
        static void SetTrip(IntPtr eng, bool on, IEnumerable<string> allowIps)
        {
            RemoveKind(eng, KindTrip);
            if (!on) return;
            var mem = new List<IntPtr>();
            try
            {
                var v4 = new List<Cond>();
                foreach (var r in Fw.BlockedV4(allowIps)) v4.Add(RangeCond(mem, TypeUint32, r[0], r[1]));
                var v6 = new List<Cond>();
                foreach (var r in Fw.BlockedV6)
                    v6.Add(RangeCond(mem, TypeBytes16, Bytes16(mem, r[0]).ToInt64(), Bytes16(mem, r[1]).ToInt64()));
                AddFilter(eng, Key(KindTrip, 0), "CPF-Trip v4", LayerV4, v4.ToArray(), ActionBlock, 1, FlagPersistent);
                AddFilter(eng, Key(KindTrip, 1), "CPF-Trip v6", LayerV6, v6.ToArray(), ActionBlock, 1, FlagPersistent);
            }
            finally { foreach (var p in mem) Marshal.FreeHGlobal(p); }
        }

        static void AddFilter(IntPtr eng, Guid key, string name, Guid layer, Cond[] conds, uint action, byte weight, uint flags)
        {
            var mem = new List<IntPtr>();
            try
            {
                int sz = Marshal.SizeOf(typeof(Cond));
                IntPtr pc = Marshal.AllocHGlobal(sz * conds.Length); mem.Add(pc);
                for (int i = 0; i < conds.Length; i++) Marshal.StructureToPtr(conds[i], pc + i * sz, false);
                var pn = Marshal.StringToHGlobalUni(name); mem.Add(pn);
                var f = new Filter
                {
                    key = key, name = pn, flags = flags, layer = layer, subLayer = SubKey,
                    weightType = TypeUint8, weight = weight, numConds = (uint)conds.Length, conds = pc, actionType = action
                };
                ulong id;
                Check(FwpmFilterAdd0(eng, ref f, IntPtr.Zero, out id), "FwpmFilterAdd(" + name + ")");
            }
            finally { foreach (var p in mem) Marshal.FreeHGlobal(p); }
        }

        // 同一字段的多个条件之间是“或”
        static Cond RangeCond(List<IntPtr> mem, uint type, long lo, long hi)
        {
            var pr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Range))); mem.Add(pr);
            Marshal.StructureToPtr(new Range { lowType = type, low = lo, highType = type, high = hi }, pr, false);
            return new Cond { field = CondRemoteAddr, match = MatchRange, type = TypeRange, value = pr };
        }

        static IntPtr Bytes16(List<IntPtr> mem, string ip)
        {
            var b = IPAddress.Parse(ip).GetAddressBytes();
            var p = Marshal.AllocHGlobal(16); mem.Add(p); Marshal.Copy(b, 0, p, 16);
            return p;
        }
    }
}
