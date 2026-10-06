using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace ChainedProxyFuse
{
    // ---------- 设置 ----------
    public class Settings
    {
        public string ExpectedIp = "";                       // 日本静态 IP
        public List<string> AllowIps = new List<string>();   // 允许直连的 IP（马来西亚服务器、直连 DNS）
        public string TunName = "singbox_tun";
        public int IntervalSec = 5;
        public int FailLimit = 2;
    }

    static class Util
    {
        public static readonly string Dir = AppDomain.CurrentDomain.BaseDirectory;
        static readonly object logLock = new object();

        public static void Log(string msg)
        {
            try
            {
                lock (logLock)
                    File.AppendAllText(Path.Combine(Dir, "fuse.log"),
                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }

        // 运行外部程序，返回标准输出；超时则杀掉
        public static string Run(string file, string args, int timeoutMs)
        {
            string err;
            return Run(file, args, timeoutMs, out err);
        }

        public static string Run(string file, string args, int timeoutMs, out string err)
        {
            err = null;
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8
                };
                using (var p = Process.Start(psi))
                {
                    var outTask = p.StandardOutput.ReadToEndAsync();
                    var errTask = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } err = "timeout"; return null; }
                    err = errTask.Result.Trim();
                    return outTask.Result;
                }
            }
            catch { return null; }
        }

        static readonly Regex Ipv4 = new Regex(@"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$");
        public static string ParseIp(string s)
        {
            if (s == null) return null;
            var m = Ipv4.Match(s);
            return m.Success ? m.Groups[1].Value : null;
        }

        public static bool IsPrivateOrLocal(string ip)
        {
            IPAddress a;
            if (!IPAddress.TryParse(ip, out a)) return true;
            var b = a.GetAddressBytes();
            if (b.Length != 4) return true;
            return b[0] == 10 || b[0] == 127 || b[0] == 0 || b[0] >= 224 ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
        }
    }

    // ---------- 读取 v2rayN 的实时状态（它启动后会删掉配置文件，所以看进程） ----------
    static class Live
    {
        class Conn { public string State, Local, Remote; public int Pid; }

        static List<Conn> Netstat()
        {
            var res = new List<Conn>();
            var text = Util.Run("netstat.exe", "-ano -p tcp", 8000);
            if (text == null) return res;
            foreach (var line in text.Split('\n'))
            {
                var t = line.Split(new[] { ' ', '\t', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                int pid;
                if (t.Length >= 5 && t[0] == "TCP" && int.TryParse(t[4], out pid))
                    res.Add(new Conn { Local = t[1], Remote = t[2], State = t[3], Pid = pid });
            }
            return res;
        }

        static HashSet<int> Pids(string name)
        {
            return new HashSet<int>(Process.GetProcessesByName(name).Select(p => p.Id));
        }

        public static bool V2rayNRunning() { return Process.GetProcessesByName("v2rayN").Length > 0; }

        static int Port(string endpoint) { return int.Parse(endpoint.Substring(endpoint.LastIndexOf(':') + 1)); }

        // 主 xray 的本地 SOCKS 中继端口；找不到返回 0。
        // v2rayN 测速时会临时多开几个 xray，所以优先选 sing-box 正连着的那个端口。
        public static int RelayPort()
        {
            var xray = Pids("xray");
            if (xray.Count == 0) return 0;
            var sb = Pids("sing-box");
            var conns = Netstat();
            var listening = conns.Where(c => c.State == "LISTENING" && xray.Contains(c.Pid) && c.Local.StartsWith("127.0.0.1:"))
                                 .Select(c => Port(c.Local)).ToList();
            foreach (var c in conns)
                if (c.State == "ESTABLISHED" && sb.Contains(c.Pid) && c.Remote.StartsWith("127.0.0.1:") && listening.Contains(Port(c.Remote)))
                    return Port(c.Remote);
            return listening.Count > 0 ? listening[0] : 0;
        }

        // sing-box 正在直连的公网地址（马来西亚服务器等）
        public static List<string> SingBoxRemotes()
        {
            var sb = Pids("sing-box");
            var set = new HashSet<string>();
            if (sb.Count == 0) return new List<string>();
            foreach (var c in Netstat())
            {
                if (!sb.Contains(c.Pid)) continue;
                if (c.State != "ESTABLISHED" && c.State != "SYN_SENT") continue;
                var ip = c.Remote.Substring(0, c.Remote.LastIndexOf(':'));
                if (!Util.IsPrivateOrLocal(ip)) set.Add(ip);
            }
            return set.ToList();
        }

        // 虚拟网卡名（按描述识别）
        public static string TunName(string fallback)
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
                if (n.Description.IndexOf("sing-tun", StringComparison.OrdinalIgnoreCase) >= 0) return n.Name;
            return fallback;
        }

        public static string RealIfaceIp(string tun)
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.OperationalStatus != OperationalStatus.Up || n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if (n.Name == tun || n.Description.IndexOf("Tunnel", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                foreach (var u in n.GetIPProperties().UnicastAddresses)
                    if (u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) return u.Address.ToString();
            }
            return null;
        }
    }

    // ---------- Windows 防火墙 ----------
    static class Fw
    {
        const string Grp = "ChainedProxyFuse";
        public const string LockName = "CPF-Lock", TripName = "CPF-Trip";

        static dynamic Pol() { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")); }

        public static bool FirewallOn()
        {
            try { dynamic p = Pol(); return p.FirewallEnabled[1] && p.FirewallEnabled[2] && p.FirewallEnabled[4]; }
            catch { return false; }
        }

        public static void RemoveAll()
        {
            dynamic p = Pol();
            var names = new List<string>();
            foreach (dynamic r in (System.Collections.IEnumerable)p.Rules)
                if (Convert.ToString(r.Grouping) == Grp) names.Add((string)r.Name);
            foreach (var n in names) p.Rules.Remove(n);
        }

        public static bool TripEnabled()
        {
            try { dynamic p = Pol(); return (bool)p.Rules.Item(TripName).Enabled; } catch { return false; }
        }

        public static bool Exists(string name)
        {
            try { dynamic p = Pol(); var r = p.Rules.Item(name); return r != null; } catch { return false; }
        }

        public static void SetTrip(bool on)
        {
            dynamic p = Pol();
            p.Rules.Item(TripName).Enabled = on;
        }

        static void Add(string name, string remote, string[] ifaces, bool enabled)
        {
            dynamic r = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            r.Name = name; r.Grouping = Grp; r.Direction = 2; r.Action = 0; r.Protocol = 256;
            r.Profiles = 0x7FFFFFFF; r.RemoteAddresses = remote;
            if (ifaces != null) r.Interfaces = ifaces.Cast<object>().ToArray();
            r.Enabled = enabled;
            Pol().Rules.Add(r);
        }

        // 建立/刷新两条规则；保留“总闸”当前的开关状态
        public static void Build(Settings s)
        {
            bool trip = TripEnabled();
            RemoveAll();
            string remote = RemoteBlocked(s.AllowIps);
            string tun = Live.TunName(s.TunName);
            var ifaces = new List<string>();   // 真实网卡（门禁）
            var all = new List<string>();      // 真实网卡 + 虚拟网卡（总闸），不含本机回环，免得把检测用的 127.0.0.1 也封掉
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                all.Add(n.Name);
                if (n.Name == tun || n.Description.IndexOf("sing-tun", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                ifaces.Add(n.Name);
            }
            Add(LockName, remote, ifaces.Count > 0 ? ifaces.ToArray() : null, true);
            Add(TripName, remote, all.Count > 0 ? all.ToArray() : null, trip);
            Util.Log("防火墙规则已刷新。放行 IP: " + string.Join(",", s.AllowIps) + "；受限网卡: " + string.Join(",", ifaces));
        }

        static uint ToU(string s)
        {
            var b = IPAddress.Parse(s).GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }
        static string FromU(long u) { return ((u >> 24) & 255) + "." + ((u >> 16) & 255) + "." + ((u >> 8) & 255) + "." + (u & 255); }

        // “全部地址 减去 白名单”，用区间表示（防火墙规则要的是要封的地址）
        static string RemoteBlocked(IEnumerable<string> ips)
        {
            var allow = new List<uint[]>();
            Action<string, string> a = (s, e) => allow.Add(new[] { ToU(s), ToU(e) });
            a("0.0.0.0", "0.0.0.0"); a("127.0.0.0", "127.255.255.255"); a("10.0.0.0", "10.255.255.255");
            a("172.16.0.0", "172.31.255.255"); a("192.168.0.0", "192.168.255.255"); a("169.254.0.0", "169.254.255.255");
            a("224.0.0.0", "239.255.255.255"); a("255.255.255.255", "255.255.255.255");
            a("223.5.5.5", "223.5.5.5"); a("223.6.6.6", "223.6.6.6");
            foreach (var ip in ips) { IPAddress x; if (IPAddress.TryParse(ip, out x) && x.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) a(ip, ip); }
            allow.Sort((p, q) => p[0].CompareTo(q[0]));

            var parts = new List<string>();
            long cursor = 0;
            foreach (var r in allow)
            {
                if (r[0] > cursor) parts.Add(Range(cursor, r[0] - 1));
                if ((long)r[1] + 1 > cursor) cursor = (long)r[1] + 1;
            }
            if (cursor <= uint.MaxValue) parts.Add(Range(cursor, uint.MaxValue));
            // IPv6：只放行 ::1、::ffff:0:0/96（IPv4 映射地址，由上面的 IPv4 规则管）、fc00::/7、fe80::/10、ff00::/8，其余公网 IPv6 全封
            parts.Add("0:0:0:0:0:0:0:2-0:0:0:0:0:fffe:ffff:ffff");
            parts.Add("0:0:0:0:1:0:0:0-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
            parts.Add("fe00::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
            parts.Add("fec0::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
            return string.Join(",", parts);
        }
        static string Range(long s, long e) { return s == e ? FromU(s) : FromU(s) + "-" + FromU(e); }
    }

    // ---------- 出口 IP 检测（用系统自带 curl） ----------
    static class Probe
    {
        static int n;
        static readonly string[] Urls = { "http://api.ipify.org", "http://ipv4.icanhazip.com", "http://ifconfig.me/ip" };
        static string Url() { return Urls[(n++) % Urls.Length]; }

        // 经代理链（xray 中继端口）看到的出口 IP
        public static string ViaRelay(int port, out string err)
        {
            return Util.ParseIp(Util.Run("curl.exe", "-sS -m 6 --noproxy * --socks5-hostname 127.0.0.1:" + port + " " + Url(), 10000, out err));
        }
        // 不指定代理，走系统路由（也就是浏览器走的那条路）
        public static string ViaSystem()
        {
            return Util.ParseIp(Util.Run("curl.exe", "-s -m 6 --noproxy * " + Url(), 10000));
        }
        // 强行绑定到真实网卡出门，门禁生效时必须失败
        public static string ViaRealNic(string ip)
        {
            return Util.ParseIp(Util.Run("curl.exe", "-s -m 5 --noproxy * --interface " + ip + " " + Url(), 9000));
        }
        public static string Country(int port)
        {
            var s = Util.Run("curl.exe", "-s -m 6 --noproxy * --socks5-hostname 127.0.0.1:" + port + " \"http://ip-api.com/line/?fields=country\"", 10000);
            return s == null ? "" : s.Trim();
        }
    }

    // ---------- 托盘程序 ----------
    enum St { Waiting, Ok, Tripped, Paused }

    class Tray : ApplicationContext
    {
        readonly Settings S;
        readonly string cfgPath = Path.Combine(Util.Dir, "fuse-config.json");
        readonly NotifyIcon ni = new NotifyIcon();
        readonly Control ui = new Control();
        readonly ToolStripMenuItem miStatus = new ToolStripMenuItem(), miRecover = new ToolStripMenuItem("恢复上网"),
            miPause = new ToolStripMenuItem("暂停保护（可正常上网，但不受保护）"), miResume = new ToolStripMenuItem("恢复保护"),
            miAuto = new ToolStripMenuItem("开机自动启动");
        readonly AutoResetEvent kick = new AutoResetEvent(false);
        readonly object fwLock = new object();
        volatile bool quitting;
        St st = St.Waiting;
        string reason = "";
        int fails, goodStreak, relayMissing;
        bool recoverReady, askedFirstRun;
        string lastProbeLog;
        System.Threading.Timer netDebounce;

        public Tray()
        {
            ui.CreateControl(); var h = ui.Handle;
            S = Load();

            miRecover.Click += (o, e) => Recover();
            miPause.Click += (o, e) => Pause();
            miResume.Click += (o, e) => { ProtectOn(); SetState(St.Waiting, "已恢复保护，等待检测"); kick.Set(); };
            miAuto.Click += (o, e) => ToggleAuto();
            var menu = new ContextMenuStrip();
            miStatus.Enabled = false;
            menu.Items.Add(miStatus); menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(miRecover); menu.Items.Add(miPause); menu.Items.Add(miResume); menu.Items.Add(new ToolStripSeparator());
            AddItem(menu, "立即检测", () => kick.Set());
            AddItem(menu, "模拟泄漏测试（真实网卡应该出不去）", () => ThreadPool.QueueUserWorkItem(_ => LeakTest(true)));
            AddItem(menu, "重新识别日本 IP", () => { S.ExpectedIp = ""; askedFirstRun = false; Save(); kick.Set(); });
            AddItem(menu, "打开日志", () => { try { Process.Start("notepad.exe", Path.Combine(Util.Dir, "fuse.log")); } catch { } });
            menu.Items.Add(miAuto); menu.Items.Add(new ToolStripSeparator());
            AddItem(menu, "退出（会解除保护）", Quit);
            ni.ContextMenuStrip = menu; ni.Visible = true;
            ni.DoubleClick += (o, e) => ni.ShowBalloonTip(4000, "链式代理保险丝", miStatus.Text, ToolTipIcon.Info);
            menu.Opening += (o, e) => { miAuto.Checked = AutoOn(); RefreshUi(); };

            // 启动：建立门禁；若上次是“已断网”则保持断网
            try
            {
                ProtectOn();
                if (Fw.TripEnabled()) { st = St.Tripped; reason = "上次断网后尚未恢复"; }
            }
            catch (Exception ex) { Util.Log("建立门禁失败: " + ex.Message); st = St.Waiting; reason = "建立防火墙规则失败: " + ex.Message; }
            RefreshUi();

            NetworkChange.NetworkAddressChanged += (o, e) => { if (netDebounce != null) netDebounce.Dispose(); netDebounce = new System.Threading.Timer(_ => { if (st != St.Paused) SafeBuild(); }, null, 2000, Timeout.Infinite); };
            var t = new Thread(Loop) { IsBackground = true }; t.Start();
        }

        static void AddItem(ContextMenuStrip m, string text, Action a)
        {
            var it = new ToolStripMenuItem(text); it.Click += (o, e) => a(); m.Items.Add(it);
        }

        Settings Load()
        {
            try { if (File.Exists(cfgPath)) return new JavaScriptSerializer().Deserialize<Settings>(File.ReadAllText(cfgPath, Encoding.UTF8)); } catch { }
            return new Settings();
        }
        void Save() { try { File.WriteAllText(cfgPath, new JavaScriptSerializer().Serialize(S), Encoding.UTF8); } catch { } }

        void SafeBuild() { lock (fwLock) { try { Fw.Build(S); } catch (Exception ex) { Util.Log("刷新防火墙失败: " + ex.Message); } } }
        void ProtectOn() { S.TunName = Live.TunName(S.TunName); lock (fwLock) { Fw.Build(S); } }

        // ---------- 状态与界面 ----------
        void SetState(St s, string why)
        {
            if (st != s || reason != why) Util.Log("状态: " + s + " - " + why);
            st = s; reason = why; RefreshUi();
        }

        void RefreshUi()
        {
            if (quitting) return;
            ui.BeginInvoke((Action)(() =>
            {
                Color c; string text;
                switch (st)
                {
                    case St.Ok: c = Color.LimeGreen; text = "正常 · 出口 " + S.ExpectedIp; break;
                    case St.Tripped: c = Color.Red; text = "已断网：" + reason + (recoverReady ? "（日本 IP 已恢复，可点“恢复上网”）" : ""); break;
                    case St.Paused: c = Color.Gray; text = "已暂停保护（不受保护）"; break;
                    default: c = Color.Gold; text = "等待/检查中：" + reason; break;
                }
                miStatus.Text = text.Length > 120 ? text.Substring(0, 120) : text;
                ni.Text = ("保险丝 · " + text).Substring(0, Math.Min(60, ("保险丝 · " + text).Length));
                miRecover.Enabled = st == St.Tripped && recoverReady;
                miPause.Visible = st != St.Paused; miResume.Visible = st == St.Paused;
                var old = ni.Icon; ni.Icon = MakeIcon(c); if (old != null) old.Dispose();
            }));
        }

        static Icon MakeIcon(Color c)
        {
            using (var bmp = new Bitmap(16, 16))
            {
                using (var g = Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                    using (var b = new SolidBrush(c)) g.FillEllipse(b, 1, 1, 14, 14);
                    g.DrawEllipse(Pens.Black, 1, 1, 13, 13);
                }
                var hIcon = bmp.GetHicon();
                var ic = (Icon)Icon.FromHandle(hIcon).Clone();
                NativeDestroy(hIcon);
                return ic;
            }
        }
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr h);
        static void NativeDestroy(IntPtr h) { DestroyIcon(h); }

        void Balloon(string title, string text, ToolTipIcon icon)
        {
            ui.BeginInvoke((Action)(() => ni.ShowBalloonTip(8000, title, text, icon)));
        }

        // ---------- 动作 ----------
        void Trip(string why)
        {
            try { lock (fwLock) { if (!Fw.Exists(Fw.TripName)) Fw.Build(S); Fw.SetTrip(true); } }
            catch (Exception ex) { Util.Log("拉闸失败: " + ex.Message); }
            recoverReady = false; goodStreak = 0;
            SetState(St.Tripped, why);
            Balloon("已断网！", why, ToolTipIcon.Error);
            try { System.Media.SystemSounds.Hand.Play(); } catch { }
        }

        void Recover()
        {
            try { lock (fwLock) Fw.SetTrip(false); } catch (Exception ex) { Util.Log("恢复失败: " + ex.Message); return; }
            recoverReady = false; fails = 0; goodStreak = 0;
            SetState(St.Ok, "手动恢复");
            Util.Log("用户点击恢复上网");
        }

        void Pause()
        {
            if (MessageBox.Show("暂停后会撤掉所有防火墙保护，电脑可以不经代理直接上网，真实 IP 可能暴露。\n\n确定暂停吗？",
                "暂停保护", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try { lock (fwLock) Fw.RemoveAll(); } catch (Exception ex) { Util.Log("撤销规则失败: " + ex.Message); }
            SetState(St.Paused, "用户暂停");
        }

        void Quit()
        {
            if (MessageBox.Show("退出后会撤掉所有防火墙保护。确定退出吗？", "退出", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            quitting = true;
            try { lock (fwLock) Fw.RemoveAll(); } catch { }
            Util.Log("用户退出，规则已撤销");
            ni.Visible = false; kick.Set();
            ExitThread();
            Environment.Exit(0);
        }

        const string TaskName = "ChainedProxyFuse";
        bool AutoOn() { return Util.Run("schtasks.exe", "/Query /TN " + TaskName, 8000) != null && Util.Run("schtasks.exe", "/Query /TN " + TaskName, 8000).Contains(TaskName); }
        void ToggleAuto()
        {
            if (AutoOn()) Util.Run("schtasks.exe", "/Delete /TN " + TaskName + " /F", 8000);
            else Util.Run("schtasks.exe", "/Create /TN " + TaskName + " /TR \"\\\"" + Application.ExecutablePath + "\\\"\" /SC ONLOGON /RL HIGHEST /F", 8000);
        }

        void LeakTest(bool show)
        {
            var ip = Live.RealIfaceIp(S.TunName);
            string msg; bool leaked = false;
            if (ip == null) msg = "找不到真实网卡的 IP，无法测试。";
            else
            {
                var r = Probe.ViaRealNic(ip);
                leaked = r != null;
                msg = leaked ? "危险！强行从真实网卡出门成功了，对方看到的是 " + r + "。门禁没有生效，请检查防火墙是否被其它软件接管。"
                             : "通过：强行从真实网卡（" + ip + "）出门被拦住了。";
            }
            Util.Log("泄漏自检: " + msg);
            if (show || leaked)
                ui.BeginInvoke((Action)(() => MessageBox.Show(msg, "泄漏自检", MessageBoxButtons.OK, leaked ? MessageBoxIcon.Error : MessageBoxIcon.Information)));
        }

        // 把 sing-box 正在直连的地址记进白名单；有新地址就刷新门禁
        void Learn()
        {
            bool changed = false;
            foreach (var ip in Live.SingBoxRemotes())
                if (!S.AllowIps.Contains(ip)) { S.AllowIps.Add(ip); changed = true; Util.Log("学到放行地址: " + ip); }
            if (changed) { Save(); SafeBuild(); }
        }

        // ---------- 巡逻循环 ----------
        void Loop()
        {
            if (!Fw.FirewallOn()) { Balloon("防火墙没开", "Windows 防火墙处于关闭状态，保护不会生效！", ToolTipIcon.Warning); Util.Log("警告：Windows 防火墙未开启"); }
            bool leakChecked = false;
            while (!quitting)
            {
                try { Tick(ref leakChecked); } catch (Exception ex) { Util.Log("巡逻异常: " + ex.Message); }
                kick.WaitOne(Math.Max(2, S.IntervalSec) * 1000);
            }
        }

        void Tick(ref bool leakChecked)
        {
            if (st == St.Paused) return;
            int port = Live.RelayPort();
            // 断网时也要学：v2rayN 重启后 sing-box 可能连到前置服务器的另一个 IP，不放行就永远检测不到恢复
            if (port != 0) Learn();

            string err = null;
            string ip = port == 0 ? null : Probe.ViaRelay(port, out err);
            if (st != St.Ok)
            {
                string line = "检测(" + st + ") 中继端口=" + port + " 结果=" + (ip ?? "失败 " + err);
                if (line != lastProbeLog) { Util.Log(line); lastProbeLog = line; }
            }

            if (port == 0) { relayMissing++; if (st != St.Tripped) reason = Live.V2rayNRunning() ? "v2rayN 在运行，但没找到代理链" : "v2rayN 没运行"; }
            else relayMissing = 0;

            if (ip != null && S.ExpectedIp == "")
            {
                if (!askedFirstRun) { askedFirstRun = true; FirstRun(port, ip); }
                return;
            }
            if (S.ExpectedIp == "") { SetState(St.Waiting, port == 0 ? "请先启动 v2rayN" : "等待检测"); return; }

            if (ip == S.ExpectedIp)
            {
                fails = 0;
                if (st == St.Tripped)
                {
                    goodStreak++;
                    if (goodStreak >= 3 && !recoverReady)
                    {
                        recoverReady = true; RefreshUi();
                        Util.Log("日本 IP 已连续 3 次检测正常，等待用户点“恢复上网”");
                        Balloon("日本 IP 已恢复", "已稳定约 15 秒。右键托盘图标点“恢复上网”。", ToolTipIcon.Info);
                    }
                    return;
                }
                // 正常状态：再看一眼浏览器走的那条路
                var sys = Probe.ViaSystem();
                if (sys != null && sys != S.ExpectedIp) { Trip("系统出口 IP 不是日本：" + sys); return; }
                SetState(St.Ok, "正常");
                if (!leakChecked) { leakChecked = true; LeakTest(false); }
            }
            else if (ip != null)
            {
                if (st != St.Tripped) Trip("出口 IP 变了：" + ip + "（应为 " + S.ExpectedIp + "）");
                goodStreak = 0;
            }
            else
            {
                goodStreak = 0; fails++;
                if (st == St.Ok && fails >= S.FailLimit) Trip(port == 0 ? "v2rayN/代理链消失" : "日本 IP 不通");
                else if (st == St.Waiting) SetState(St.Waiting, reason == "" ? "等待代理链" : reason);
            }
        }

        void FirstRun(int port, string ip)
        {
            var country = Probe.Country(port);
            ui.BeginInvoke((Action)(() =>
            {
                var r = MessageBox.Show("当前通过代理链看到的出口 IP 是：\n\n    " + ip + "  " + country + "\n\n这个就是你的日本静态 IP 吗？\n点“是”后，以后这个 IP 一变或不通，就会断网。",
                    "首次设置", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (r == DialogResult.Yes)
                {
                    S.ExpectedIp = ip; Save(); Util.Log("记住日本 IP: " + ip);
                    if (!AutoOn() && MessageBox.Show("要设置开机自动启动吗？（推荐，否则重启后没有断网保护）", "开机启动", MessageBoxButtons.YesNo) == DialogResult.Yes) ToggleAuto();
                    kick.Set();
                }
                else askedFirstRun = true;
            }));
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            bool created;
            using (var m = new Mutex(true, "ChainedProxyFuse.Single", out created))
            {
                if (!created) return;
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new Tray());
            }
        }
    }
}
