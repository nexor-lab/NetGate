using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using NetGateCore;

[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyVersion("0.0.0.0")]
namespace NetGateCore
{
	public sealed class EngineOptions
	{
		public string ListenAddress = "0.0.0.0";

		public int ListenPort = 8888;

		public int MaxConnections = 1024;

		public bool VerboseLog;

		public int ConnectTimeoutMs = 15000;

		public int DnsTimeoutMs = 2500;

		public string LogFile = "NetGateEngine.log";

		public string[] DohServers = new string[4] { "1.1.1.1", "1.0.0.1", "8.8.8.8", "223.5.5.5" };
	}
	public sealed class Device
	{
		public string Mac = "";

		public string Ip = "";

		public string Name = "";

		// 用户端自己设置的名称（聊天/文件传输里显示的名字）
		public string Nick = "";

		public string Who = "";

		public long Up;

		public long Down;

		public long LimitUpKB;

		public long LimitDownKB;

		public long CurUp;

		public long CurDown;

		public long SessionUp;

		public long SessionDown;

		public int Active;

		public bool Online;

		public bool Paused;

		public bool Allowed;

		public bool Pending;

		public bool Kicked;

		// 局域网群聊禁言：控制端可以把某台设备设为「禁言」，所有客户端的群聊都会忽略它
		public bool ChatMuted;

		// 客户端群聊用的实例 ID（FileTransferService.LocalId），禁言按它下发
		public string ChatId = "";

		public DateTime LoginAt = DateTime.Now;

		public DateTime LastSeen = DateTime.Now;

		public string ClientVersion = "";

		public readonly object Sync = new object();

		public double TokensUp;

		public double TokensDown;

		public DateTime LastFillUp = DateTime.UtcNow;

		public DateTime LastFillDown = DateTime.UtcNow;

		public string ToJson()
		{
			return string.Format(CultureInfo.InvariantCulture, "{{\"mac\":\"{0}\",\"ip\":\"{1}\",\"name\":\"{2}\",\"nick\":\"{18}\",\"user\":\"{3}\",\"up\":{4},\"down\":{5},\"limitUp\":{6},\"limitDown\":{7},\"curUp\":{8},\"curDown\":{9},\"active\":{10},\"online\":{11},\"paused\":{12},\"allowed\":{16},\"pending\":{17},\"chatmuted\":{19},\"chatid\":\"{20}\",\"login\":\"{13:O}\",\"last\":\"{14:O}\",\"version\":\"{15}\"}}", Esc(Mac), Esc(Ip), Esc(Name), Esc(Who), Up, Down, LimitUpKB, LimitDownKB, CurUp, CurDown, Active, B(Online), B(Paused), LoginAt, LastSeen, Esc(ClientVersion), B(Allowed), B(Pending), Esc(Nick), B(ChatMuted), Esc(ChatId));
		}

		private static string B(bool v)
		{
			if (!v)
			{
				return "false";
			}
			return "true";
		}

		private static string Esc(string s)
		{
			if (string.IsNullOrEmpty(s))
			{
				return "";
			}
			StringBuilder stringBuilder = new StringBuilder(s.Length + 8);
			foreach (char c in s)
			{
				if (c == '\\')
				{
					stringBuilder.Append("\\\\");
				}
				else if (c == '"')
				{
					stringBuilder.Append("\\\"");
				}
				else if (c < ' ')
				{
					stringBuilder.Append(' ');
				}
				else
				{
					stringBuilder.Append(c);
				}
			}
			return stringBuilder.ToString();
		}
	}
	internal sealed class Peer
	{
		public Socket Sock;

		public Device Dev;

		public byte[] Buffer = new byte[32768];

		public int Count;

		public byte[] Slice(int from, int len)
		{
			byte[] array = new byte[len];
			System.Buffer.BlockCopy(Buffer, from, array, 0, len);
			return array;
		}
	}
	internal sealed class HttpHead
	{
		public string Method = "";

		public string RawTarget = "";

		public string Path = "";

		public string Host = "";

		public int Port = 80;

		public List<string> Lines = new List<string>();

		public int ContentLength;
	}
	public sealed class NetGateServer
	{
		private static readonly object _logLock = new object();

		private static readonly byte[] CRLFCRLF = new byte[4] { 13, 10, 13, 10 };

		public static string LogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "engine.log");

		private readonly EngineOptions _opts;

		private readonly ConcurrentDictionary<string, Device> _devices = new ConcurrentDictionary<string, Device>(StringComparer.OrdinalIgnoreCase);

		private readonly HashSet<string> _allowedMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		private readonly object _allowedLock = new object();

		private readonly ConcurrentDictionary<string, long[]> _limitValues = new ConcurrentDictionary<string, long[]>(StringComparer.OrdinalIgnoreCase);

		private readonly ConcurrentDictionary<string, bool> _mutedMacs = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

		private readonly ConcurrentDictionary<string, IPAddress[]> _dnsCache = new ConcurrentDictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase);

		private readonly List<DohClient> _doh = new List<DohClient>();

		private TcpListener _listener;

		private int _active;

		private Task _accept;

		public volatile bool Running;

		public string LastError = "";

		public readonly object StateLock = new object();

		public string PasswordHash = "";

		public string GatewayName = "";

		public string Kicked = "";

		public string AllowMode = "";

		public long TotalUp;

		public long TotalDown;

		public static int MaxRecv;

		public int Port
		{
			get
			{
				return _opts.ListenPort;
			}
		}

		public NetGateServer(EngineOptions opts)
		{
			_opts = opts;
			string[] dohServers = opts.DohServers;
			foreach (string server in dohServers)
			{
				_doh.Add(new DohClient(server));
			}
		}

		public static NetGateServer Create(EngineOptions o)
		{
			return new NetGateServer(o);
		}

		public void Start()
		{
			IPAddress address = IPAddress.Any;
			if (!string.IsNullOrEmpty(_opts.ListenAddress))
			{
				IPAddress.TryParse(_opts.ListenAddress, out address);
			}
			try
			{
				_listener = new TcpListener(address, _opts.ListenPort);
				_listener.Server.ExclusiveAddressUse = true;
				_listener.Start(256);
			}
			catch (Exception ex)
			{
				LastError = ex.Message;
				throw;
			}
			Running = true;
			Log(string.Concat("proxy listening on ", address, ":", _opts.ListenPort));
			_accept = Task.Run(() => AcceptLoopAsync());
			Task.Run(() => MaintenanceLoopAsync());
		}

		public void Stop()
		{
			Running = false;
			try
			{
				_listener.Stop();
			}
			catch
			{
			}
		}

		public bool Wait(TimeSpan t)
		{
			if (_accept != null)
			{
				return _accept.Wait(t);
			}
			return true;
		}

		public static string HashPassword(string pwd)
		{
			byte[] bytes = Encoding.UTF8.GetBytes("NetGate|" + (pwd ?? ""));
			SHA256 sHA = SHA256.Create();
			byte[] array = sHA.ComputeHash(bytes);
			StringBuilder stringBuilder = new StringBuilder();
			for (int i = 0; i < array.Length; i++)
			{
				stringBuilder.Append(array[i].ToString("x2"));
			}
			return stringBuilder.ToString();
		}

		public Device GetOrCreate(string mac, string ip)
		{
			if (string.IsNullOrEmpty(mac))
			{
				mac = "unknown";
			}
			string key = mac.ToLowerInvariant();
			Device orAdd = _devices.GetOrAdd(key, delegate(string m)
			{
				Device device = new Device();
				device.Mac = m;
				device.LoginAt = DateTime.Now;
				lock (_allowedLock)
				{
					device.Allowed = _allowedMacs.Contains(m);
				}
				long[] limits;
				if (_limitValues.TryGetValue(m, out limits))
				{
					device.LimitUpKB = limits[0];
					device.LimitDownKB = limits[1];
				}
				bool muted;
				if (_mutedMacs.TryGetValue(m, out muted))
				{
					device.ChatMuted = muted;
				}
				return device;
			});
			orAdd.LastSeen = DateTime.Now;
			if (!string.IsNullOrEmpty(ip))
			{
				orAdd.Ip = ip;
			}
			return orAdd;
		}

		public Device Find(string mac)
		{
			if (string.IsNullOrEmpty(mac))
			{
				return null;
			}
			Device value;
			_devices.TryGetValue(mac.ToLowerInvariant(), out value);
			return value;
		}

		public void UpdateSession(string mac, string ip, string name, string user, string version)
		{
			UpdateSession(mac, ip, name, user, version, null);
		}

		public void UpdateSession(string mac, string ip, string name, string user, string version, string nick)
		{
			Device orCreate = GetOrCreate(mac, ip);
			lock (orCreate.Sync)
			{
				if (!string.IsNullOrEmpty(name))
				{
					orCreate.Name = name;
				}
				if (!string.IsNullOrEmpty(nick))
				{
					orCreate.Nick = nick;
				}
				if (!string.IsNullOrEmpty(user))
				{
					orCreate.Who = user;
				}
				if (!string.IsNullOrEmpty(version))
				{
					orCreate.ClientVersion = version;
				}
				if (!orCreate.Online)
				{
					orCreate.LoginAt = DateTime.Now;
				}
				orCreate.Online = true;
				orCreate.LastSeen = DateTime.Now;
			}
			Log("device online: " + orCreate.Mac + " ip=" + orCreate.Ip + " name=" + orCreate.Name + " nick=" + orCreate.Nick);
		}

		public void DeviceOffline(string mac)
		{
			Device device = Find(mac);
			if (device != null)
			{
				lock (device.Sync)
				{
					device.Online = false;
					device.Active = 0;
				}
				Log("device offline: " + device.Mac);
			}
		}

		public void SetLimit(string mac, long upKB, long downKB)
		{
			if (string.IsNullOrEmpty(mac))
			{
				return;
			}
			string text = mac.ToLowerInvariant();
			long[] array = new long[2];
			array[0] = Math.Max(0L, upKB);
			array[1] = Math.Max(0L, downKB);
			if (array[0] == 0L && array[1] == 0L)
			{
				long[] old;
				_limitValues.TryRemove(text, out old);
			}
			else
			{
				_limitValues[text] = array;
			}
			Device device = Find(text);
			if (device != null)
			{
				lock (device.Sync)
				{
					device.LimitUpKB = array[0];
					device.LimitDownKB = array[1];
				}
			}
			Log("device limit: " + mac + " up=" + upKB + "KB/s down=" + downKB + "KB/s");
		}

		public static string HashProbe(string pwd)
		{
			return HashPassword(pwd);
		}

		public bool Verify(string pwd)
		{
			return HashPassword(pwd) == PasswordHash;
		}

		public void SetPaused(string mac, bool paused)
		{
			Device device = Find(mac);
			if (device != null)
			{
				lock (device.Sync)
				{
					device.Paused = paused;
				}
				Log("device " + (paused ? "paused" : "resumed") + ": " + mac);
			}
		}

		// ---- 局域网群聊禁言：控制端标记，客户端执行 ----

		// 客户端上报自己的群聊实例 ID（CHAT 报文里用的就是这个 ID）
		public void SetChatId(string mac, string cid)
		{
			if (string.IsNullOrEmpty(mac) || string.IsNullOrEmpty(cid))
			{
				return;
			}
			Device device = Find(mac);
			if (device != null)
			{
				lock (device.Sync)
				{
					device.ChatId = cid.Trim();
				}
			}
		}

		public void SetChatMuted(string mac, bool muted)
		{
			if (string.IsNullOrEmpty(mac))
			{
				return;
			}
			string text = mac.ToLowerInvariant();
			if (muted)
			{
				_mutedMacs[text] = true;
			}
			else
			{
				bool removed;
				_mutedMacs.TryRemove(text, out removed);
			}
			Device device = Find(text);
			if (device != null)
			{
				lock (device.Sync)
				{
					device.ChatMuted = muted;
				}
			}
			Log("device chatmuted=" + muted + ": " + mac);
		}

		public bool IsChatMuted(string mac)
		{
			Device device = Find(mac);
			if (device == null)
			{
				return false;
			}
			lock (device.Sync)
			{
				return device.ChatMuted;
			}
		}

		// 下发给客户端的禁言名单（群聊实例 ID，逗号分隔）
		public string MutedCids()
		{
			List<string> list = new List<string>();
			foreach (Device device in new List<Device>(_devices.Values))
			{
				lock (device.Sync)
				{
					if (device.ChatMuted && !string.IsNullOrEmpty(device.ChatId) && !list.Contains(device.ChatId))
					{
						list.Add(device.ChatId);
					}
				}
			}
			return string.Join(",", list.ToArray());
		}

		// 被禁言设备的 IP 列表：控制端自己过滤群聊消息用（客户端不用改）
		public string MutedIps()
		{
			List<string> list = new List<string>();
			foreach (Device device in new List<Device>(_devices.Values))
			{
				lock (device.Sync)
				{
					if (device.ChatMuted && !string.IsNullOrEmpty(device.Ip) && !list.Contains(device.Ip))
					{
						list.Add(device.Ip);
					}
				}
			}
			return string.Join(",", list.ToArray());
		}

		// 按 IP 找设备：群聊成员列表里只有 IP，没有 MAC
		public Device FindByIp(string ip)
		{
			if (string.IsNullOrEmpty(ip))
			{
				return null;
			}
			foreach (Device device in new List<Device>(_devices.Values))
			{
				lock (device.Sync)
				{
					if (string.Equals(device.Ip, ip, StringComparison.OrdinalIgnoreCase))
					{
						return device;
					}
				}
			}
			return null;
		}

		public void Kick(string mac)
		{
			Device device = Find(mac);
			if (device != null)
			{
				lock (device.Sync)
				{
					device.Online = false;
					device.Kicked = true;
					device.Active = 0;
				}
			}
			lock (StateLock)
			{
				List<string> list = (from k in Kicked.Split(';')
					where k.Length > 0 && !k.Equals(mac, StringComparison.OrdinalIgnoreCase)
					select k).ToList();
				list.Insert(0, mac ?? "");
				Kicked = string.Join(";", list);
			}
			Log("device kicked: " + mac);
		}

		public void Unkick(string mac)
		{
			Device device = Find(mac);
			if (device != null)
			{
				lock (device.Sync)
				{
					device.Kicked = false;
				}
			}
			lock (StateLock)
			{
				IEnumerable<string> values = from k in Kicked.Split(';')
					where k.Length > 0 && !k.Equals(mac, StringComparison.OrdinalIgnoreCase)
					select k;
				Kicked = string.Join(";", values);
			}
		}

		public string KickedJson()
		{
			lock (StateLock)
			{
				List<string> values = (from k in Kicked.Split(';')
					where k.Length > 0
					select "\"" + k + "\"").ToList();
				return "[" + string.Join(",", values) + "]";
			}
		}

		private void RefreshDevices()
		{
			try
			{
				DateTime now = DateTime.Now;
				List<Device> list = new List<Device>(_devices.Values);
				List<string> list2 = new List<string>();
				foreach (Device device in list)
				{
					lock (device.Sync)
					{
						if (device.Online && (now - device.LastSeen).TotalSeconds > 60.0)
						{
							device.Online = false;
							device.Active = 0;
						}
						// 清掉只发过扫描 hello、没有 IP 的幽灵设备
						if (!device.Online && !device.Allowed && !device.Pending && string.IsNullOrEmpty(device.Ip) && (now - device.LastSeen).TotalSeconds > 120.0)
						{
							list2.Add(device.Mac);
						}
					}
				}
				foreach (string mac in list2)
				{
					Device device2;
					_devices.TryRemove(mac.ToLowerInvariant(), out device2);
				}
			}
			catch
			{
			}
		}

		public string DevicesJson()
		{
			RefreshDevices();
			List<Device> list = (from d in new List<Device>(_devices.Values)
				orderby d.Online descending, d.Name
				select d).ToList();
			List<string> list2 = new List<string>();
			foreach (Device item in list)
			{
				list2.Add(item.ToJson());
			}
			return "[" + string.Join(",", list2) + "]";
		}

		public void SetAllowed(string mac, bool allowed)
		{
			if (string.IsNullOrEmpty(mac))
			{
				return;
			}
			string text = mac.ToLowerInvariant();
			lock (_allowedLock)
			{
				if (allowed)
				{
					_allowedMacs.Add(text);
				}
				else
				{
					_allowedMacs.Remove(text);
				}
			}
			Device device = Find(text);
			if (device != null)
			{
				lock (device.Sync)
				{
					device.Allowed = allowed;
					device.Pending = false;
					if (allowed)
					{
						device.Kicked = false;
					}
				}
			}
			if (allowed)
			{
				Unkick(text);
			}
			Log("device allowed=" + allowed + ": " + mac);
		}

		public bool IsAllowed(string mac)
		{
			if (string.IsNullOrEmpty(mac))
			{
				return false;
			}
			Device device = Find(mac);
			if (device != null)
			{
				lock (device.Sync)
				{
					return device.Allowed;
				}
			}
			lock (_allowedLock)
			{
				return _allowedMacs.Contains(mac);
			}
		}

		public bool IsPending(string mac)
		{
			Device device = Find(mac);
			if (device == null)
			{
				return false;
			}
			lock (device.Sync)
			{
				return device.Pending;
			}
		}

		public bool IsOnline(string mac)
		{
			Device device = Find(mac);
			if (device == null)
			{
				return false;
			}
			lock (device.Sync)
			{
				return device.Online;
			}
		}

		public void Reset()
		{
			lock (StateLock)
			{
			}
			List<string> list = _devices.Keys.ToList();
			foreach (string item in list)
			{
				Device value;
				_devices.TryRemove(item, out value);
			}
			TotalUp = 0L;
			TotalDown = 0L;
			Log("devices reset");
		}

		public int OnlineCount()
		{
			RefreshDevices();
			return _devices.Values.Count((Device d) => d.Online);
		}

		public string StatsJson()
		{
			return string.Format(CultureInfo.InvariantCulture, "{{\"ok\":true,\"running\":{0},\"port\":{1},\"active\":{2},\"devices\":{3},\"online\":{4},\"up\":{5},\"down\":{6},\"name\":\"{7}\"}}", Running ? "true" : "false", _opts.ListenPort, _active, _devices.Count, OnlineCount(), TotalUp, TotalDown, JsonEsc(GatewayName));
		}

		private static string JsonEsc(string s)
		{
			if (string.IsNullOrEmpty(s))
			{
				return "";
			}
			return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
		}

		public static string Enc(string s)
		{
			return "Q" + Convert.ToBase64String(Encoding.UTF8.GetBytes(s ?? ""));
		}

		public static string Dec(string s)
		{
			if (s == null)
			{
				return "";
			}
			if (s.StartsWith("Q", StringComparison.Ordinal))
			{
				try
				{
					return Encoding.UTF8.GetString(Convert.FromBase64String(s.Substring(1)));
				}
				catch
				{
					return "";
				}
			}
			return s;
		}

		private async Task AcceptLoopAsync()
		{
			while (Running)
			{
				Socket s;
				try
				{
					s = await _listener.AcceptSocketAsync().ConfigureAwait(false);
				}
				catch
				{
					if (!Running)
					{
						break;
					}
					continue;
				}
				if (Interlocked.Increment(ref _active) > _opts.MaxConnections)
				{
					Interlocked.Decrement(ref _active);
					try
					{
						s.Close();
					}
					catch
					{
					}
				}
				else
				{
					Socket sock = s;
					Task t0 = HandleAsync(sock);
					GC.KeepAlive(t0);
				}
			}
		}

		private async Task HandleAsync(Socket s)
		{
			Peer peer = new Peer
			{
				Sock = s
			};
			try
			{
				s.NoDelay = true;
				if (await PeekAsync(peer, 20000).ConfigureAwait(false))
				{
					byte b = peer.Buffer[0];
					if (b == 67 || b == 71 || b == 80 || b == 72 || b == 68 || b == 79)
					{
						await HandleHttpAsync(peer).ConfigureAwait(false);
					}
				}
			}
			catch (Exception ex)
			{
				if (_opts.VerboseLog)
				{
					Log("conn error: " + ex.Message);
				}
			}
			finally
			{
				Device dev = peer.Dev;
				if (dev != null)
				{
					lock (dev.Sync)
					{
						dev.Active = Math.Max(0, dev.Active - 1);
					}
				}
				try
				{
					s.Shutdown(SocketShutdown.Both);
				}
				catch
				{
				}
				try
				{
					s.Close();
				}
				catch
				{
				}
				Interlocked.Decrement(ref _active);
			}
		}

		private async Task<bool> PeekAsync(Peer peer, int timeout)
		{
			Task<int> read = peer.Sock.ReceiveAsync(new ArraySegment<byte>(peer.Buffer), SocketFlags.None);
			if (await Task.WhenAny(read, Task.Delay(timeout)).ConfigureAwait(false) != read)
			{
				return false;
			}
			peer.Count = await read.ConfigureAwait(false);
			return peer.Count > 0;
		}

		private async Task HandleHttpAsync(Peer peer)
		{
			int end;
			while (true)
			{
				end = IndexOf(peer.Buffer, peer.Count, CRLFCRLF);
				if (end >= 0)
				{
					break;
				}
				if (peer.Count >= peer.Buffer.Length)
				{
					await ReplyAsync(peer.Sock, 400, "header").ConfigureAwait(false);
					return;
				}
				int i = await peer.Sock.ReceiveAsync(new ArraySegment<byte>(peer.Buffer, peer.Count, peer.Buffer.Length - peer.Count), SocketFlags.None).ConfigureAwait(false);
				if (i <= 0)
				{
					return;
				}
				peer.Count += i;
			}
			HttpHead head = ParseHead(peer.Buffer, peer.Count, end);
			if (head == null)
			{
				await ReplyAsync(peer.Sock, 400, "bad").ConfigureAwait(false);
				return;
			}
			int bodyStart = end + 4;
			int bodyLen = Math.Max(0, head.ContentLength);
			while (peer.Count < bodyStart + bodyLen && peer.Count < peer.Buffer.Length)
			{
				int j = await peer.Sock.ReceiveAsync(new ArraySegment<byte>(peer.Buffer, peer.Count, peer.Buffer.Length - peer.Count), SocketFlags.None).ConfigureAwait(false);
				if (j <= 0)
				{
					break;
				}
				peer.Count += j;
			}
			if (peer.Count < bodyStart + bodyLen)
			{
				await ReplyAsync(peer.Sock, 400, "body").ConfigureAwait(false);
				return;
			}
			byte[] payload = peer.Slice(bodyStart, bodyLen);
			if (head.Method.Equals("GET", StringComparison.OrdinalIgnoreCase) && head.Path.StartsWith("/__netgate/auth", StringComparison.Ordinal))
			{
				await ReplyAuthAsync(peer.Sock, head).ConfigureAwait(false);
				return;
			}
			if (head.Method.Equals("GET", StringComparison.OrdinalIgnoreCase) && head.Path.StartsWith("/__netgate", StringComparison.Ordinal))
			{
				await ReplyStatusAsync(peer.Sock, head.Path).ConfigureAwait(false);
				return;
			}
			Device dev;
			string authMsg = Authorize(head, out dev);
			if (authMsg != null)
			{
				await ReplyAsync(peer.Sock, (authMsg == "pending") ? 403 : 407, authMsg).ConfigureAwait(false);
				return;
			}
			peer.Dev = dev;
			bool lockTaken = false;
			object obj = default(object);
			bool paused;
			try
			{
				object sync;
				obj = (sync = dev.Sync);
				Monitor.Enter(sync, ref lockTaken);
				dev.Active++;
				dev.LastSeen = DateTime.Now;
				dev.Online = true;
				paused = dev.Paused;
			}
			finally
			{
				if (lockTaken)
				{
					Monitor.Exit(obj);
				}
			}
			if (paused)
			{
				await ReplyAsync(peer.Sock, 403, "paused").ConfigureAwait(false);
			}
			else if (head.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
			{
				string[] hp = SplitHostPort(head.RawTarget, 443);
				if (hp == null)
				{
					await ReplyAsync(peer.Sock, 400, "connect").ConfigureAwait(false);
				}
				else
				{
					await TunnelAsync(peer, hp[0], int.Parse(hp[1], CultureInfo.InvariantCulture), payload).ConfigureAwait(false);
				}
			}
			else
			{
				await ForwardHttpAsync(peer, head, payload).ConfigureAwait(false);
			}
		}

		private string Authorize(HttpHead head, out Device dev)
		{
			dev = null;
			string text = null;
			string text2 = null;
			foreach (string line in head.Lines)
			{
				if (line.StartsWith("X-NetGate-Mac:", StringComparison.OrdinalIgnoreCase))
				{
					text = line.Substring(14).Trim();
				}
				else if (line.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase))
				{
					text2 = line.Substring(20).Trim();
				}
			}
			if (string.IsNullOrEmpty(text))
			{
				return "no-device";
			}
			if (!Regex.IsMatch(text, "^[0-9a-fA-F]{12}$"))
			{
				return "bad-device";
			}
			lock (StateLock)
			{
				string[] array = Kicked.Split(';');
				foreach (string text3 in array)
				{
					if (text3.Length > 0 && text3.Equals(text, StringComparison.OrdinalIgnoreCase))
					{
						return "kicked";
					}
				}
				if (text2 != null && PasswordHash.Length > 0 && text2.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
				{
					string text4 = "";
					try
					{
						text4 = Encoding.UTF8.GetString(Convert.FromBase64String(text2.Substring(6).Trim()));
					}
					catch
					{
						text4 = "";
					}
					int num = text4.IndexOf(':');
					string pwd = ((num >= 0) ? text4.Substring(num + 1) : "");
					if (HashPassword(pwd) == PasswordHash)
					{
						Device orCreate = GetOrCreate(text, null);
						bool allowed;
						lock (orCreate.Sync)
						{
							allowed = orCreate.Allowed;
							if (!allowed)
							{
								orCreate.Pending = true;
							}
						}
						dev = orCreate;
						if (!allowed)
						{
							return "pending";
						}
						return null;
					}
				}
			}
			return "auth";
		}

		private static Dictionary<string, string> ParseQuery(string path)
		{
			Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			int num = path.IndexOf('?');
			if (num >= 0)
			{
				string[] array = path.Substring(num + 1).Split('&');
				foreach (string text in array)
				{
					string[] array2 = text.Split(new char[1] { '=' }, 2);
					dictionary[array2[0]] = ((array2.Length > 1) ? Uri.UnescapeDataString(array2[1]) : "");
				}
			}
			return dictionary;
		}

		private async Task ReplyAuthAsync(Socket s, HttpHead head)
		{
			Device dev;
			string res = Authorize(head, out dev);
			if (dev != null)
			{
				Dictionary<string, string> dictionary = ParseQuery(head.Path);
				UpdateSession(dev.Mac, dictionary.ContainsKey("ip") ? dictionary["ip"] : "", Dec(dictionary.ContainsKey("name") ? dictionary["name"] : ""), Dec(dictionary.ContainsKey("user") ? dictionary["user"] : ""), dictionary.ContainsKey("v") ? dictionary["v"] : "1.1", Dec(dictionary.ContainsKey("nick") ? dictionary["nick"] : ""));
				SetChatId(dev.Mac, dictionary.ContainsKey("cid") ? dictionary["cid"] : "");
			}
			int code = ((res == null) ? 200 : ((res == "pending") ? 403 : 407));
			string key = res ?? "ok";
			bool allowed = dev != null && dev.Allowed;
			bool pending = dev != null && dev.Pending;
			bool kicked = dev != null && dev.Kicked;
			string body = "{\"ok\":" + ((code == 200) ? "true" : "false") + ",\"allowed\":" + (allowed ? "true" : "false") + ",\"pending\":" + (pending ? "true" : "false") + ",\"kicked\":" + (kicked ? "true" : "false") + ",\"state\":\"" + key + "\",\"muted\":\"" + JsonEsc(MutedCids()) + "\"}";
			object[] array = new object[10] { "HTTP/1.1 ", code, " ", null, null, null, null, null, null, null };
			object obj;
			switch (code)
			{
			default:
				obj = "Proxy Authentication Required";
				break;
			case 403:
				obj = "Forbidden";
				break;
			case 200:
				obj = "OK";
				break;
			}
			array[3] = obj;
			array[4] = "\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-NetGate: ";
			array[5] = key;
			array[6] = "\r\nContent-Length: ";
			array[7] = Encoding.UTF8.GetByteCount(body).ToString(CultureInfo.InvariantCulture);
			array[8] = "\r\nConnection: close\r\n\r\n";
			array[9] = body;
			await SendRawAsync(s, string.Concat(array)).ConfigureAwait(false);
		}

		private async Task ReplyStatusAsync(Socket s, string path)
		{
			Dictionary<string, string> q = ParseQuery(path);
			string mac = (q.ContainsKey("mac") ? q["mac"].ToLowerInvariant() : "");
			string ip = (q.ContainsKey("ip") ? q["ip"] : "");
			string name = Dec(q.ContainsKey("name") ? q["name"] : "");
			string user = Dec(q.ContainsKey("user") ? q["user"] : "");
			string nick = Dec(q.ContainsKey("nick") ? q["nick"] : "");
			string ver = (q.ContainsKey("v") ? q["v"] : "");
			string cid = (q.ContainsKey("cid") ? q["cid"].Trim() : "");
			bool kicked = false;
			if (mac.Length > 0)
			{
				// 扫描探测包只有 mac/name/user，没有 ip/nick；不要为它建档，
				// 否则每次扫描都会在控制端留下“不知道的电脑”。
				bool hasSession = q.ContainsKey("ip") || q.ContainsKey("nick");
				if (hasSession || Find(mac) != null || IsAllowed(mac))
				{
					UpdateSession(mac, ip, name, user, ver, nick);
					SetChatId(mac, cid);
				}
				lock (StateLock)
				{
					kicked = Kicked.Split(';').Any((string k) => k.Length > 0 && k.Equals(mac, StringComparison.OrdinalIgnoreCase));
				}
			}
			bool allowed = IsAllowed(mac);
			bool pending = IsPending(mac);
			bool paused = false;
			Device dd = Find(mac);
			if (dd != null)
			{
				bool lockTaken = false;
				object obj = default(object);
				try
				{
					object sync;
					obj = (sync = dd.Sync);
					Monitor.Enter(sync, ref lockTaken);
					paused = dd.Paused;
				}
				finally
				{
					if (lockTaken)
					{
						Monitor.Exit(obj);
					}
				}
			}
			string body = "{\"ok\":true,\"online\":true,\"kicked\":" + (kicked ? "true" : "false") + ",\"allowed\":" + (allowed ? "true" : "false") + ",\"pending\":" + (pending ? "true" : "false") + ",\"paused\":" + (paused ? "true" : "false") + ",\"onlineCount\":" + OnlineCount().ToString(CultureInfo.InvariantCulture) + ",\"name\":\"" + JsonEsc(GatewayName) + "\",\"port\":" + Port.ToString(CultureInfo.InvariantCulture) + ",\"muted\":\"" + JsonEsc(MutedCids()) + "\"}";
			await SendRawAsync(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-NetGate: hello\r\nProxy-Agent: NetGate/1.0\r\nContent-Length: " + Encoding.UTF8.GetByteCount(body).ToString(CultureInfo.InvariantCulture) + "\r\nConnection: close\r\n\r\n" + body).ConfigureAwait(false);
		}

		private async Task ForwardHttpAsync(Peer peer, HttpHead head, byte[] payload)
		{
			string host = head.Host;
			string path = head.Path;
			int port = head.Port;
			if (string.IsNullOrEmpty(host) || !path.StartsWith("/", StringComparison.Ordinal))
			{
				await ReplyAsync(peer.Sock, 400, "target").ConfigureAwait(false);
				return;
			}
			Socket remote = null;
			try
			{
				remote = await ConnectAnyAsync(await ResolveAsync(host).ConfigureAwait(false), port).ConfigureAwait(false);
				byte[] req = Encoding.UTF8.GetBytes(BuildForwardRequest(head, host, port, path));
				await SendAllAsync(remote, req, req.Length).ConfigureAwait(false);
				if (payload.Length > 0)
				{
					if (!(await ThrottleAsync(peer.Dev, payload.Length, true).ConfigureAwait(false)))
					{
						await ReplyAsync(peer.Sock, 403, "paused").ConfigureAwait(false);
						return;
					}
					await SendAllAsync(remote, payload, payload.Length).ConfigureAwait(false);
					Count(peer, payload.Length, true);
				}
				await CopyResponseAsync(remote, peer).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				if (_opts.VerboseLog)
				{
					Log("forward fail " + host + ":" + port + " " + ex.Message);
				}
				try
				{
					Task obj = ReplyAsync(peer.Sock, 502, "connect");
					GC.KeepAlive(obj);
				}
				catch
				{
				}
			}
			finally
			{
				CloseQuietly(remote);
				try
				{
					peer.Sock.Shutdown(SocketShutdown.Send);
				}
				catch
				{
				}
			}
		}

		private static string BuildForwardRequest(HttpHead h, string host, int port, string path)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append(h.Method).Append(' ').Append(path)
				.Append(" HTTP/1.1\r\n");
			foreach (string line in h.Lines)
			{
				string text = line.ToLowerInvariant();
				if (!text.StartsWith("connection:", StringComparison.Ordinal) && !text.StartsWith("proxy-connection:", StringComparison.Ordinal) && !text.StartsWith("proxy-authorization:", StringComparison.Ordinal) && !text.StartsWith("host:", StringComparison.Ordinal) && !text.StartsWith("content-length:", StringComparison.Ordinal) && !text.StartsWith("x-netgate", StringComparison.Ordinal))
				{
					stringBuilder.Append(line).Append("\r\n");
				}
			}
			if (h.ContentLength > 0)
			{
				stringBuilder.Append("Content-Length: ").Append(h.ContentLength.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
			}
			stringBuilder.Append("Host: ").Append(HostPortText(host, port)).Append("\r\nConnection: close\r\n\r\n");
			return stringBuilder.ToString();
		}

		private static void Rcv(int max)
		{
			try
			{
				if (max > MaxRecv)
				{
					MaxRecv = max;
					AppDomain.CurrentDomain.SetData("maxrecv", 0);
				}
			}
			catch
			{
			}
		}

		private async Task CopyResponseAsync(Socket remote, Peer peer)
		{
			byte[] buf = new byte[16384];
			try
			{
				while (true)
				{
					int i;
					try
					{
						i = await remote.ReceiveAsync(new ArraySegment<byte>(buf), SocketFlags.None).ConfigureAwait(false);
					}
					catch
					{
						break;
					}
					if (i > 0)
					{
						Device dev = peer.Dev;
						if (await ThrottleAsync(dev, i, false).ConfigureAwait(false))
						{
							try
							{
								await SendAllAsync(peer.Sock, buf, i).ConfigureAwait(false);
							}
							catch
							{
								break;
							}
							Count(peer, i, false);
							continue;
						}
						break;
					}
					break;
				}
			}
			finally
			{
			}
		}

		private async Task TunnelAsync(Peer peer, string host, int port, byte[] payload)
		{
			Socket remote = null;
			try
			{
				remote = await ConnectAnyAsync(await ResolveAsync(host).ConfigureAwait(false), port).ConfigureAwait(false);
				await SendRawAsync(peer.Sock, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: NetGate/1.0\r\n\r\n").ConfigureAwait(false);
				if (payload.Length > 0)
				{
					await SendAllAsync(remote, payload, payload.Length).ConfigureAwait(false);
					Count(peer, payload.Length, true);
				}
				Task a = PumpAsync(peer.Sock, remote, peer, true);
				Task b = PumpAsync(remote, peer.Sock, peer, false);
				await Task.WhenAny(a, b).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				if (_opts.VerboseLog)
				{
					Log("tunnel fail " + host + ":" + port + " " + ex.Message);
				}
				try
				{
					Task obj = ReplyAsync(peer.Sock, 502, "connect");
					GC.KeepAlive(obj);
				}
				catch
				{
				}
			}
			finally
			{
				CloseQuietly(remote);
			}
		}

		private void Count(Peer peer, int n, bool up)
		{
			Device dev = peer.Dev;
			if (dev != null)
			{
				if (up)
				{
					Interlocked.Add(ref dev.SessionUp, n);
					Interlocked.Add(ref TotalUp, n);
				}
				else
				{
					Interlocked.Add(ref dev.SessionDown, n);
					Interlocked.Add(ref TotalDown, n);
				}
			}
		}

		private async Task PumpAsync(Socket src, Socket dst, Peer peer, bool up)
		{
			byte[] buf = new byte[8192];
			try
			{
				while (true)
				{
					int i;
					try
					{
						i = await src.ReceiveAsync(new ArraySegment<byte>(buf), SocketFlags.None).ConfigureAwait(false);
					}
					catch
					{
						break;
					}
					if (i > 0 && await ThrottleAsync(peer.Dev, i, up).ConfigureAwait(false))
					{
						try
						{
							await SendAllAsync(dst, buf, i).ConfigureAwait(false);
						}
						catch
						{
							break;
						}
						Count(peer, i, up);
						continue;
					}
					break;
				}
			}
			finally
			{
				try
				{
					dst.Shutdown(SocketShutdown.Send);
				}
				catch
				{
				}
			}
		}

		private async Task<bool> ThrottleAsync(Device d, int n, bool up)
		{
			if (d == null)
			{
				return true;
			}
			object obj = default(object);
			while (true)
			{
				bool lockTaken = false;
				bool paused;
				bool kicked;
				int wait;
				try
				{
					object sync;
					obj = (sync = d.Sync);
					Monitor.Enter(sync, ref lockTaken);
					paused = d.Paused;
					kicked = d.Kicked;
					if (!paused && !kicked)
					{
						long rate = (up ? d.LimitUpKB : d.LimitDownKB) * 1024;
						if (rate <= 0)
						{
							return true;
						}
						DateTime utcNow = DateTime.UtcNow;
						DateTime dateTime = (up ? d.LastFillUp : d.LastFillDown);
						double totalSeconds = (utcNow - dateTime).TotalSeconds;
						if (totalSeconds > 0.0)
						{
							if (up)
							{
								d.TokensUp += (double)rate * totalSeconds;
								d.LastFillUp = utcNow;
							}
							else
							{
								d.TokensDown += (double)rate * totalSeconds;
								d.LastFillDown = utcNow;
							}
						}
						double num = Math.Max(Math.Max((double)rate * 0.25, 32768.0), (double)n * 2.0);
						if (up)
						{
							if (d.TokensUp > num)
							{
								d.TokensUp = num;
							}
							if (d.TokensUp >= (double)n)
							{
								d.TokensUp -= n;
								return true;
							}
							wait = (int)Math.Min(200.0, Math.Max(5.0, Math.Ceiling(((double)n - d.TokensUp) * 1000.0 / (double)rate)));
						}
						else
						{
							if (d.TokensDown > num)
							{
								d.TokensDown = num;
							}
							if (d.TokensDown >= (double)n)
							{
								d.TokensDown -= n;
								return true;
							}
							wait = (int)Math.Min(200.0, Math.Max(5.0, Math.Ceiling(((double)n - d.TokensDown) * 1000.0 / (double)rate)));
						}
					}
					else
					{
						wait = 100;
					}
				}
				finally
				{
					if (lockTaken)
					{
						Monitor.Exit(obj);
					}
				}
				if (paused || kicked)
				{
					break;
				}
				await Task.Delay(wait).ConfigureAwait(false);
			}
			return false;
		}

		public Task<IPAddress[]> ResolveAsync(string host)
		{
			IPAddress address;
			if (IPAddress.TryParse(host, out address))
			{
				return Task.FromResult(new IPAddress[1] { address });
			}
			IPAddress[] value;
			if (_dnsCache.TryGetValue(host, out value))
			{
				return Task.FromResult(value);
			}
			return ResolveUncachedAsync(host);
		}

		private async Task<IPAddress[]> ResolveUncachedAsync(string host)
		{
			ConcurrentBag<IPAddress> bag = new ConcurrentBag<IPAddress>();
			Task<IPAddress[]>[] tasks = _doh.Select((DohClient d) => d.QueryAsync(host)).ToArray();
			try
			{
				await Task.WhenAny(Task.WhenAll(tasks), Task.Delay(_opts.DnsTimeoutMs)).ConfigureAwait(false);
			}
			catch
			{
			}
			Task<IPAddress[]>[] array = tasks;
			foreach (Task<IPAddress[]> task in array)
			{
				if (task.Status != TaskStatus.RanToCompletion || task.Result == null)
				{
					continue;
				}
				IPAddress[] result = task.Result;
				foreach (IPAddress iPAddress in result)
				{
					if (iPAddress.AddressFamily == AddressFamily.InterNetwork)
					{
						bag.Add(iPAddress);
					}
				}
			}
			if (bag.IsEmpty)
			{
				try
				{
					IPAddress[] hostAddresses = Dns.GetHostAddresses(host);
					foreach (IPAddress item in hostAddresses)
					{
						bag.Add(item);
					}
				}
				catch
				{
				}
			}
			IPAddress[] list = bag.Distinct().Take(4).ToArray();
			if (list.Length == 0)
			{
				throw new SocketException(11001);
			}
			_dnsCache[host] = list;
			return list;
		}

		private async Task MaintenanceLoopAsync()
		{
			DateTime prev = DateTime.UtcNow;
			while (Running)
			{
				await Task.Delay(1000).ConfigureAwait(false);
				DateTime now = DateTime.UtcNow;
				double dt = Math.Max(0.2, (now - prev).TotalSeconds);
				prev = now;
				foreach (Device value in _devices.Values)
				{
					lock (value.Sync)
					{
						long sessionUp = value.SessionUp;
						long sessionDown = value.SessionDown;
						value.SessionUp = 0L;
						value.SessionDown = 0L;
						value.Up += sessionUp;
						value.Down += sessionDown;
						value.CurUp = (long)Math.Round((double)sessionUp / dt);
						value.CurDown = (long)Math.Round((double)sessionDown / dt);
						if (value.Active <= 0 && (now - value.LastSeen).TotalSeconds > 25.0)
						{
							value.Online = false;
						}
					}
				}
				if (_dnsCache.Count > 5000)
				{
					_dnsCache.Clear();
				}
			}
		}

		private static HttpHead ParseHead(byte[] data, int count, int end)
		{
			string @string = Encoding.UTF8.GetString(data, 0, end);
			string[] array = @string.Split(new string[1] { "\r\n" }, StringSplitOptions.None);
			if (array.Length == 0)
			{
				return null;
			}
			string[] array2 = array[0].Split(' ');
			if (array2.Length < 2)
			{
				return null;
			}
			HttpHead httpHead = new HttpHead();
			httpHead.Method = array2[0];
			httpHead.RawTarget = array2[1];
			httpHead.Lines = (from l in array.Skip(1)
				where l.Length > 0
				select l).ToList();
			foreach (string line in httpHead.Lines)
			{
				int result;
				if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
				{
					string[] array3 = SplitHostPort(line.Substring(5).Trim(), 80);
					if (array3 != null)
					{
						httpHead.Host = array3[0];
						httpHead.Port = int.Parse(array3[1], CultureInfo.InvariantCulture);
					}
				}
				else if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) && int.TryParse(line.Substring(15).Trim(), out result))
				{
					httpHead.ContentLength = result;
				}
			}
			httpHead.Path = httpHead.RawTarget;
			if (!httpHead.RawTarget.StartsWith("/", StringComparison.Ordinal))
			{
				int num = httpHead.RawTarget.IndexOf("://", StringComparison.Ordinal);
				if (num > 0)
				{
					string text = httpHead.RawTarget.Substring(num + 3);
					int num2 = text.IndexOf('/');
					string s = ((num2 < 0) ? text : text.Substring(0, num2));
					httpHead.Path = ((num2 < 0) ? "/" : text.Substring(num2));
					string[] array4 = SplitHostPort(s, 80);
					if (array4 != null)
					{
						httpHead.Host = array4[0];
						httpHead.Port = int.Parse(array4[1], CultureInfo.InvariantCulture);
					}
				}
			}
			return httpHead;
		}

		public static string[] SplitHostPort(string s, int defaultPort)
		{
			if (string.IsNullOrEmpty(s))
			{
				return null;
			}
			s = s.Trim();
			int result = -1;
			string text;
			if (s.StartsWith("[", StringComparison.Ordinal))
			{
				int num = s.IndexOf(']');
				if (num < 0)
				{
					return null;
				}
				text = s.Substring(1, num - 1);
				string text2 = s.Substring(num + 1);
				if (text2.StartsWith(":", StringComparison.Ordinal))
				{
					int.TryParse(text2.Substring(1), out result);
				}
			}
			else
			{
				int num2 = s.LastIndexOf(':');
				if (num2 > 0)
				{
					text = s.Substring(0, num2);
					int.TryParse(s.Substring(num2 + 1), out result);
				}
				else
				{
					text = s;
				}
			}
			if (string.IsNullOrEmpty(text))
			{
				return null;
			}
			if (result <= 0)
			{
				result = defaultPort;
			}
			return new string[2]
			{
				text,
				result.ToString(CultureInfo.InvariantCulture)
			};
		}

		private static string HostPortText(string host, int port)
		{
			if (host.Contains(":"))
			{
				return "[" + host + "]:" + port.ToString(CultureInfo.InvariantCulture);
			}
			return host + ":" + port.ToString(CultureInfo.InvariantCulture);
		}

		private static int IndexOf(byte[] data, int n, byte[] pat)
		{
			for (int i = 0; i + pat.Length <= n; i++)
			{
				bool flag = true;
				for (int j = 0; j < pat.Length; j++)
				{
					if (data[i + j] != pat[j])
					{
						flag = false;
						break;
					}
				}
				if (flag)
				{
					return i;
				}
			}
			return -1;
		}

		private static async Task<Socket> ConnectAnyAsync(IPAddress[] ips, int port)
		{
			Exception last = null;
			foreach (IPAddress a in ips)
			{
				if (a == null || a.AddressFamily != AddressFamily.InterNetwork)
				{
					continue;
				}
				Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
				{
					NoDelay = true
				};
				try
				{
					Task t = s.ConnectAsync(new IPEndPoint(a, port));
					if (await Task.WhenAny(t, Task.Delay(15000)).ConfigureAwait(false) == t)
					{
						await t.ConfigureAwait(false);
						return s;
					}
					s.Close();
					last = new TimeoutException("timeout");
				}
				catch (Exception ex)
				{
					last = ex;
					try
					{
						s.Close();
					}
					catch
					{
					}
				}
			}
			throw last ?? new SocketException(10051);
		}

		private static async Task SendAllAsync(Socket s, byte[] data, int len)
		{
			int sent = 0;
			while (sent < len)
			{
				int num = sent + await s.SendAsync(new ArraySegment<byte>(data, sent, len - sent), SocketFlags.None).ConfigureAwait(false);
				sent = num;
			}
		}

		private static async Task SendRawAsync(Socket s, string text)
		{
			byte[] b = Encoding.UTF8.GetBytes(text);
			await SendAllAsync(s, b, b.Length).ConfigureAwait(false);
		}

		private static string ErrorBody(int code, string key)
		{
			string text;
			string text2;
			switch (key)
			{
			case "no-device":
				text = "NetGate: device not registered";
				text2 = "Please open the <b>NetGate Client</b> on this computer and enter the password.";
				break;
			case "kicked":
				text = "NetGate: access revoked";
				text2 = "The control PC has disconnected this computer. Contact the administrator.";
				break;
			case "paused":
				text = "NetGate: internet paused";
				text2 = "The control PC has paused internet access for this computer.";
				break;
			case "pending":
				text = "NetGate: waiting for approval";
				text2 = "Your password is correct. The control PC must approve this computer before it can use the internet. Ask the administrator.";
				break;
			case "auth":
				text = "NetGate: password required";
				text2 = "You are not authorized. Open the NetGate Client and enter the password.";
				break;
			case "connect":
				text = "NetGate: cannot open site";
				text2 = "The control computer could not reach this site.";
				break;
			default:
				text = "NetGate: request error";
				text2 = "Bad request (" + code + ").";
				break;
			}
			return "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + text + "</title></head><body style=\"font-family:Segoe UI,Microsoft YaHei,sans-serif;padding:32px;background:#f6f8fb;color:#1f2937\"><div style=\"max-width:520px;margin:40px auto;background:#fff;border-radius:12px;padding:28px;box-shadow:0 6px 24px rgba(0,0,0,.08)\"><h2 style=\"margin-top:0\">" + text + "</h2><p>" + text2 + "</p><p style=\"color:#6b7280;font-size:13px\">NetGate Proxy &middot; " + code + "</p></div></body></html>";
		}

		private static async Task ReplyAsync(Socket s, int code, string key)
		{
			string body = ErrorBody(code, key);
			object obj;
			switch (code)
			{
			default:
				obj = "Error";
				break;
			case 403:
				obj = "Forbidden";
				break;
			case 407:
				obj = "Proxy Authentication Required";
				break;
			}
			string reason = (string)obj;
			string text = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + Encoding.UTF8.GetByteCount(body).ToString(CultureInfo.InvariantCulture) + "\r\nConnection: close\r\nX-NetGate: " + key + "\r\nProxy-Agent: NetGate/1.0\r\n\r\n" + body;
			await SendRawAsync(s, text).ConfigureAwait(false);
		}

		private static void CloseQuietly(Socket s)
		{
			try
			{
				if (s != null)
				{
					s.Close();
				}
			}
			catch
			{
			}
		}

		public static void Log(string msg)
		{
			try
			{
				lock (_logLock)
				{
					File.AppendAllText(LogPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " [engine] " + msg + "\r\n", Encoding.UTF8);
				}
			}
			catch
			{
			}
		}
	}
	internal sealed class DohClient
	{
		private readonly string _server;

		private readonly ConcurrentDictionary<string, IPAddress[]> _cache = new ConcurrentDictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase);

		private DateTime _failingUntil = DateTime.MinValue;

		public DohClient(string server)
		{
			_server = server;
		}

		public async Task<IPAddress[]> QueryAsync(string name)
		{
			IPAddress[] hit;
			if (_cache.TryGetValue(name, out hit))
			{
				return hit;
			}
			if (DateTime.UtcNow < _failingUntil)
			{
				return null;
			}
			string url = "https://" + _server + "/dns-query?name=" + Uri.EscapeDataString(name) + "&type=A";
			HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
			req.Headers.Add("accept", "application/dns-json");
			req.UserAgent = "NetGate/1.0";
			req.Timeout = 3500;
			req.ReadWriteTimeout = 3500;
			try
			{
				HttpWebResponse httpWebResponse = (HttpWebResponse)(await req.GetResponseAsync().ConfigureAwait(false));
				using (HttpWebResponse resp = httpWebResponse)
				{
					using (StreamReader reader = new StreamReader(resp.GetResponseStream()))
					{
						string txt = await reader.ReadToEndAsync().ConfigureAwait(false);
						IPAddress[] ips = (from v in (from Match m in Regex.Matches(txt, "\"data\"\\s*:\\s*\"((?:\\d{1,3}\\.){3}\\d{1,3})\"")
								select m.Groups[1].Value).Distinct()
							select IPAddress.Parse(v)).ToArray();
						if (ips.Length > 0)
						{
							_cache[name] = ips;
						}
						return (ips.Length == 0) ? null : ips;
					}
				}
			}
			catch
			{
				_failingUntil = DateTime.UtcNow.AddSeconds(30.0);
				return null;
			}
		}
	}
}
namespace NetGateApp
{
	internal static class Program
	{
		public static bool DebugMode;

		public static bool SelfTest;

		public static bool SelfTestDone;

		private static Mutex instanceMutex;

		public static string DebugLog
		{
			get
			{
				return Path.Combine(DataDir, "NetGateDebug.log");
			}
		}

		public static string SelfPath
		{
			get
			{
				return Application.ExecutablePath;
			}
		}

		public static string DataDir
		{
			get
			{
				string text = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data");
				try
				{
					Directory.CreateDirectory(text);
					return text;
				}
				catch
				{
					string text2 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetGate");
					Directory.CreateDirectory(text2);
					return text2;
				}
			}
		}

		public static string ProgramDataDir
		{
			get
			{
				return DataDir;
			}
		}

		public static string LocalDir
		{
			get
			{
				return DataDir;
			}
		}

		[STAThread]
		private static void Main(string[] args)
		{
			Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
			AppDomain.CurrentDomain.UnhandledException += delegate(object sender, UnhandledExceptionEventArgs e)
			{
				LogFatal("Unhandled", e.ExceptionObject as Exception);
			};
			Application.ThreadException += delegate(object sender, ThreadExceptionEventArgs e)
			{
				LogFatal("ThreadException", e.Exception);
			};
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);
			bool admin = IsAdmin();
			bool flag = false;
#if CLIENT
			flag = true;
#endif
			foreach (string text in args)
			{
				string text2 = text.ToLowerInvariant();
				if (text2 == "--client")
				{
					flag = true;
				}
				if (text2 == "--admin")
				{
					flag = false;
				}
				if (text2 == "--debug")
				{
					DebugMode = true;
				}
				if (text2 == "--selftest")
				{
					SelfTest = true;
					DebugMode = true;
				}
			}
			if (HasArg(args, "--firewall-setup"))
			{
				try
				{
					if (IsAdmin())
					{
						FirewallRepairResult repair = Firewall.Repair("File", ClientFirewallPorts());
						if (repair.Ok)
						{
							MarkFirewallDone();
							LogFirewall("--firewall-setup ok: " + repair.Message);
						}
						else
						{
							// 失败就不要写标记，否则以后每次启动都以为已经放行过，再也不重试
							MarkFirewallFail();
							LogFirewall("--firewall-setup FAIL: " + repair.Message);
						}
					}
				}
				catch
				{
				}
				return;
			}
			if (!SelfTest && !HasArg(args, "--lock") && !HasArg(args, "--firewall-setup"))
			{
				EnsureSingleInstance(flag);
			}
			try
			{
				if (flag)
				{
					RunClient(args);
				}
				else
				{
					RunAdmin(admin);
				}
			}
			catch (Exception ex)
			{
				LogFatal("Main", ex);
				Dbg("FATAL: " + ex);
				MessageBox.Show(ex.Message, "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
		}

		public static void LogFatal(string tag, Exception ex)
		{
			try
			{
				string contents = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " [" + tag + "] " + ((ex == null) ? "" : ex.ToString()) + "\r\n";
				File.AppendAllText(Path.Combine(DataDir, "client-error.log"), contents, Encoding.UTF8);
			}
			catch
			{
			}
		}

		public static void Dbg(string msg)
		{
			if (!DebugMode)
			{
				return;
			}
			try
			{
				File.AppendAllText(DebugLog, DateTime.Now.ToString("HH:mm:ss.fff") + " " + msg + "\r\n", Encoding.UTF8);
			}
			catch
			{
			}
		}

		public static bool HasArg(string[] args, string name)
		{
			if (args == null)
			{
				return false;
			}
			foreach (string a in args)
			{
				if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			return false;
		}

		// 同一角色只允许一个实例；后台运行的程序再次双击时给出明确提示，避免重复监听端口。
		private static void EnsureSingleInstance(bool client)
		{
			try
			{
				string name = (client ? "Local\\NetGateClient_" : "Local\\NetGateAdmin_") + Environment.UserName;
				bool createdNew;
				// 控制端从普通权限提权重启时，旧进程可能还没完全退出，稍等重试
				for (int i = 0; i < 15; i++)
				{
					Mutex mutex = new Mutex(true, name, out createdNew);
					if (createdNew)
					{
						instanceMutex = mutex;
						return;
					}
					mutex.Dispose();
					Thread.Sleep(100);
				}
				MessageBox.Show(client ? "NetGate 上网助手已在后台运行。\r\n请从任务栏右下角托盘打开。" : "NetGate 控制端已在运行。\r\n请从任务栏右下角托盘打开。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Information);
				Environment.Exit(0);
			}
			catch
			{
				// 创建互斥体失败时不阻止程序启动
			}
		}

		public static bool IsAdmin()
		{
			try
			{
				WindowsIdentity current = WindowsIdentity.GetCurrent();
				return new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator);
			}
			catch
			{
				return false;
			}
		}

		public static bool RelaunchElevated(string exe, string extraArgs)
		{
			try
			{
				ProcessStartInfo processStartInfo = new ProcessStartInfo();
				processStartInfo.FileName = exe;
				processStartInfo.Arguments = extraArgs;
				processStartInfo.UseShellExecute = true;
				processStartInfo.Verb = "runas";
				Process.Start(processStartInfo);
				return true;
			}
			catch
			{
				return false;
			}
		}
		// 标记文件里带上版本号：老版本写的 firewall.ok 一律视为「未配置」，
		// 升级后第一次启动会重新放行一次端口，避免旧版把失败结果缓存成成功。
		private const string FirewallMarkerVersion = "v2";

		private static string FirewallMarkerPath
		{
			get
			{
				return Path.Combine(DataDir, "firewall.ok");
			}
		}

		public static bool FirewallDone()
		{
			try
			{
				if (!File.Exists(FirewallMarkerPath))
				{
					return false;
				}
				return File.ReadAllText(FirewallMarkerPath, Encoding.UTF8).IndexOf(FirewallMarkerVersion, StringComparison.OrdinalIgnoreCase) >= 0;
			}
			catch
			{
				return false;
			}
		}

		private static void MarkFirewallDone()
		{
			try
			{
				Directory.CreateDirectory(DataDir);
				File.WriteAllText(FirewallMarkerPath, FirewallMarkerVersion + " ok " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Encoding.UTF8);
				try
				{
					File.Delete(FirewallFailPath);
				}
				catch
				{
				}
			}
			catch
			{
			}
		}

		private static string FirewallFailPath
		{
			get
			{
				return Path.Combine(DataDir, "firewall.fail");
			}
		}

		// 提权后 netsh 仍然失败（组策略拦、安全软件回滚等），记一笔并冷却一天，
		// 免得每次启动都弹一次 UAC 却永远放不开。
		private static void MarkFirewallFail()
		{
			try
			{
				Directory.CreateDirectory(DataDir);
				File.WriteAllText(FirewallFailPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Encoding.UTF8);
			}
			catch
			{
			}
		}

		private static bool FirewallFailedRecently()
		{
			try
			{
				if (!File.Exists(FirewallFailPath))
				{
					return false;
				}
				DateTime dateTime;
				if (!DateTime.TryParse(File.ReadAllText(FirewallFailPath, Encoding.UTF8).Trim(), out dateTime))
				{
					return false;
				}
				return (DateTime.Now - dateTime).TotalHours < 24.0;
			}
			catch
			{
				return false;
			}
		}

		private static int[] ClientFirewallPorts()
		{
			int[] array = new int[11];
			for (int i = 0; i < 11; i++)
			{
				array[i] = 8895 + i;
			}
			return array;
		}

		public static void LogFirewall(string msg)
		{
			try
			{
				Directory.CreateDirectory(DataDir);
				File.AppendAllText(Path.Combine(DataDir, "firewall.log"),
					DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + "\r\n", Encoding.UTF8);
			}
			catch
			{
			}
		}

		private static void EnsureClientFirewall()
		{
			try
			{
				if (FirewallDone())
				{
					return;
				}
				if (IsAdmin())
				{
					FirewallRepairResult repair = Firewall.Repair("File", ClientFirewallPorts());
					LogFirewall("client(admin) repair: " + repair.Message);
					if (repair.Ok)
					{
						MarkFirewallDone();
					}
					else
					{
						MarkFirewallFail();
					}
					return;
				}
				if (FirewallFailedRecently())
				{
					LogFirewall("client firewall skipped: 上次提权放行失败，24 小时内不再重复弹 UAC（可删 data\\firewall.fail 后重试）");
					return;
				}
				ProcessStartInfo processStartInfo = new ProcessStartInfo();
				processStartInfo.FileName = SelfPath;
				processStartInfo.Arguments = "--client --firewall-setup" + (DebugMode ? " --debug" : "");
				processStartInfo.UseShellExecute = true;
				processStartInfo.Verb = "runas";
				Process.Start(processStartInfo);
				for (int i = 0; i < 60; i++)
				{
					if (FirewallDone())
					{
						break;
					}
					Thread.Sleep(100);
				}
				LogFirewall((FirewallDone() ? "client elevate ok" : "client elevate timeout/failed") + "（之后按需重试）");
			}
			catch (Exception ex)
			{
				Dbg("client firewall skipped: " + ex.Message);
				LogFirewall("client firewall skipped: " + ex.Message);
			}
		}

		private static void RunAdmin(bool admin)
		{
			if (!admin)
			{
				if (RelaunchElevated(SelfPath, "--admin" + (DebugMode ? " --debug" : "")))
				{
					Application.Exit();
				}
				else
				{
					MessageBox.Show("控制端需要管理员权限（用于开放防火墙端口）。\r\n请在系统弹窗里选择“是”后重试。", "NetGate 控制端", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
				}
			}
			else
			{
				// 控制端也随启动监听文件传输端口（以前只在引擎启动成功后才监听）
				FileTransferService.EnsureStarted();
				AdminConfig adminConfig = AdminConfig.Load();
				bool firstRun = string.IsNullOrEmpty(adminConfig.Password);
				int[] mainPorts = new int[12];
				mainPorts[0] = adminConfig.Port;
				for (int i = 0; i < 11; i++)
				{
					mainPorts[i + 1] = 8895 + i;
				}
				try
				{
					Firewall.CleanupLegacy();
					FirewallRepairResult repair = Firewall.Repair("Main", mainPorts);
					LogFirewall("admin repair " + adminConfig.Port + "/8895-8905: " + repair.Message);
				}
				catch
				{
				}
				StartFirewallGuard(mainPorts);
				Application.Run(new AdminForm(adminConfig, firstRun));
			}
		}

		// 运行中看门狗：如果程序跑着的时候 Windows 又因为换网络/弹窗写入了入站阻止规则，
		// 一分钟内自动清掉，不用重启程序，也不用用户去防火墙里手动改。
		private static void StartFirewallGuard(int[] ports)
		{
			try
			{
				Thread thread = new Thread((ThreadStart)delegate
				{
					int loop = 0;
					while (true)
					{
						Thread.Sleep(60000);
						loop++;
						try
						{
							int num = Firewall.RemoveSelfBlockRules();
							if (num > 0)
							{
								LogFirewall("self-heal: 运行中又清除了入站阻止规则 " + num + " 条");
							}
							// 每 5 分钟确认端口 / 程序规则还在；被安全软件删掉就自动重建
							if (loop % 5 == 0 && !Firewall.RulesPresent("Main"))
							{
								FirewallRepairResult repair = Firewall.Repair("Main", ports);
								LogFirewall("guard repair: " + repair.Message);
							}
						}
						catch
						{
						}
					}
				});
				thread.IsBackground = true;
				thread.Name = "NetGateFirewallGuard";
				thread.Start();
			}
			catch
			{
			}
		}

		private static void RunClient(string[] args)
		{
			SystemProxy.RecoverIfStale();
			try
			{
				AppDomain.CurrentDomain.ProcessExit += delegate
				{
					try
					{
						SystemProxy.Restore();
					}
					catch
					{
					}
				};
			}
			catch
			{
			}
			EnsureClientFirewall();
			// 用户端一启动就监听文件传输端口，这样别的电脑扫描时能立刻发现本机，
			// 而不是等用户手动打开「文件传输」窗口。
			FileTransferService.EnsureStarted();

			if (HasArg(args, "--lock") && !IsAdmin())
			{
				try
				{
					ProcessStartInfo processStartInfo = new ProcessStartInfo();
					processStartInfo.FileName = SelfPath;
					processStartInfo.Arguments = "--client --lock" + (DebugMode ? " --debug" : "");
					processStartInfo.UseShellExecute = true;
					processStartInfo.Verb = "runas";
					Process.Start(processStartInfo);
					Application.Exit();
					return;
				}
				catch (Exception ex)
				{
					LogFatal("ElevateFailed(continue normal)", ex);
				}
			}
			ClientForm form = new ClientForm();
			if (SelfTest)
			{
				form.SelfTestMode = true;
				form.ScanFinished += delegate
				{
					Dbg("SELFTEST-OK scan finished");
					form.BeginInvoke((MethodInvoker)delegate
					{
						form.Close();
					});
				};
				System.Windows.Forms.Timer t = new System.Windows.Forms.Timer
				{
					Interval = 12000
				};
				t.Tick += delegate
				{
					t.Stop();
					Dbg("SELFTEST-TIMEOUT scan did not finish");
					form.Close();
				};
				form.Shown += delegate
				{
					t.Start();
				};
			}
			Application.Run(form);
		}
	}
	internal static class Util
	{
		public static string LanIPv4()
		{
			try
			{
				string text = null;
				NetworkInterface[] allNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
				foreach (NetworkInterface networkInterface in allNetworkInterfaces)
				{
					if (networkInterface.OperationalStatus != OperationalStatus.Up || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
					{
						continue;
					}
					foreach (UnicastIPAddressInformation unicastAddress in networkInterface.GetIPProperties().UnicastAddresses)
					{
						if (unicastAddress.Address.AddressFamily != AddressFamily.InterNetwork)
						{
							continue;
						}
						string text2 = unicastAddress.Address.ToString();
						if (!text2.StartsWith("127.") && !text2.StartsWith("169.254."))
						{
							if (text2.StartsWith("10.") || text2.StartsWith("192.168.") || Is172Private(text2))
							{
								return text2;
							}
							if (text == null)
							{
								text = text2;
							}
						}
					}
				}
				return text ?? "127.0.0.1";
			}
			catch
			{
				return "127.0.0.1";
			}
		}

		public static List<string> LanPrefixes()
		{
			List<string> gatewayPrefixes = new List<string>();
			List<string> allPrefixes = new List<string>();
			try
			{
				NetworkInterface[] allNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
				foreach (NetworkInterface networkInterface in allNetworkInterfaces)
				{
					if (networkInterface.OperationalStatus != OperationalStatus.Up || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
					{
						continue;
					}
					IPInterfaceProperties properties = networkInterface.GetIPProperties();
					bool hasGateway = properties.GatewayAddresses.Count > 0;
					foreach (UnicastIPAddressInformation unicastAddress in properties.UnicastAddresses)
					{
						if (unicastAddress.Address.AddressFamily != AddressFamily.InterNetwork)
						{
							continue;
						}
						string text = unicastAddress.Address.ToString();
						if (text.StartsWith("127.") || text.StartsWith("169.254."))
						{
							continue;
						}
						int num = text.LastIndexOf('.');
						if (num > 0)
						{
							string item = text.Substring(0, num);
							if (!allPrefixes.Contains(item))
							{
								allPrefixes.Add(item);
							}
							if (hasGateway && !gatewayPrefixes.Contains(item))
							{
								gatewayPrefixes.Add(item);
							}
						}
					}
				}
			}
			catch
			{
			}
			// 优先只扫有默认网关的网段，避免把虚拟网卡 / VPN 的网段也扫一遍
			if (gatewayPrefixes.Count > 0)
			{
				return gatewayPrefixes;
			}
			if (allPrefixes.Count > 0)
			{
				return allPrefixes;
			}
			string text2 = LanIPv4();
			int num2 = text2.LastIndexOf('.');
			if (num2 > 0)
			{
				allPrefixes.Add(text2.Substring(0, num2));
			}
			return allPrefixes;
		}

		private static bool Is172Private(string ip)
		{
			if (!ip.StartsWith("172."))
			{
				return false;
			}
			string[] array = ip.Split('.');
			if (array.Length < 2)
			{
				return false;
			}
			int result;
			if (!int.TryParse(array[1], out result))
			{
				return false;
			}
			if (result >= 16)
			{
				return result <= 31;
			}
			return false;
		}

		public static string MachineId()
		{
			string s = Environment.MachineName + "|" + Environment.UserName + "|netgate";
			using (SHA256 sHA = SHA256.Create())
			{
				byte[] array = sHA.ComputeHash(Encoding.UTF8.GetBytes(s));
				StringBuilder stringBuilder = new StringBuilder();
				for (int i = 0; i < 6; i++)
				{
					stringBuilder.Append(array[i].ToString("x2"));
				}
				return stringBuilder.ToString();
			}
		}

		public static string FmtBytes(double b)
		{
			if (b < 1024.0)
			{
				return string.Format("{0:N0} B", b);
			}
			if (b < 1048576.0)
			{
				return string.Format("{0:N1} KB", b / 1024.0);
			}
			if (b < 1073741824.0)
			{
				return string.Format("{0:N1} MB", b / 1024.0 / 1024.0);
			}
			return string.Format("{0:N2} GB", b / 1024.0 / 1024.0 / 1024.0);
		}

		public static string FmtRate(double b)
		{
			if (b < 1024.0)
			{
				return string.Format("{0:N0} B/s", b);
			}
			if (b < 1048576.0)
			{
				return string.Format("{0:N0} KB/s", b / 1024.0);
			}
			return string.Format("{0:N1} MB/s", b / 1024.0 / 1024.0);
		}

		public static string FmtLimit(long downKb, long upKb)
		{
			if (downKb <= 0 && upKb <= 0)
			{
				return "不限速";
			}
			string text = "";
			if (downKb > 0)
			{
				text = text + "下载 " + FmtKbPerSec(downKb);
			}
			if (upKb > 0)
			{
				text = text + ((text.Length > 0) ? " / " : "") + "上传 " + FmtKbPerSec(upKb);
			}
			return text;
		}

		public static string FmtKbPerSec(long kb)
		{
			if (kb >= 1024)
			{
				return string.Format("{0:0.##} MB/s", (double)kb / 1024.0);
			}
			return kb + " KB/s";
		}

		public static string Q(string s)
		{
			return Uri.EscapeDataString(s ?? "");
		}

		public static string NewPassword(int len)
		{
			byte[] array = new byte[len];
			using (RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create())
			{
				randomNumberGenerator.GetBytes(array);
			}
			StringBuilder stringBuilder = new StringBuilder();
			byte[] array2 = array;
			foreach (byte b in array2)
			{
				stringBuilder.Append("abcdefghjkmnpqrstuvwxyz23456789"[(int)b % "abcdefghjkmnpqrstuvwxyz23456789".Length]);
			}
			return stringBuilder.ToString();
		}

		public static string JsonField(string json, string key)
		{
			if (json == null)
			{
				return null;
			}
			string text = "\"" + key + "\":";
			int num = json.IndexOf(text, StringComparison.Ordinal);
			if (num < 0)
			{
				return null;
			}
			for (num += text.Length; num < json.Length && json[num] == ' '; num++)
			{
			}
			if (num >= json.Length)
			{
				return null;
			}
			if (json[num] == '"')
			{
				num++;
				StringBuilder stringBuilder = new StringBuilder();
				while (num < json.Length)
				{
					char c = json[num];
					if (c == '\\' && num + 1 < json.Length)
					{
						char c2 = json[num + 1];
						if (c2 == 'u' && num + 5 < json.Length)
						{
							int result;
							if (int.TryParse(json.Substring(num + 2, 4), NumberStyles.HexNumber, null, out result))
							{
								stringBuilder.Append((char)result);
							}
							num += 6;
							continue;
						}
						switch (c2)
						{
						case 'n':
							stringBuilder.Append('\n');
							break;
						case 'r':
							stringBuilder.Append('\r');
							break;
						default:
							stringBuilder.Append(c2);
							break;
						}
						num += 2;
					}
					else
					{
						if (c == '"')
						{
							break;
						}
						stringBuilder.Append(c);
						num++;
					}
				}
				return stringBuilder.ToString();
			}
			int num2 = num;
			for (; num < json.Length && json[num] != ',' && json[num] != '}' && json[num] != ']'; num++)
			{
			}
			return json.Substring(num2, num - num2).Trim();
		}

		public static List<string> JsonObjects(string json)
		{
			List<string> list = new List<string>();
			if (string.IsNullOrEmpty(json))
			{
				return list;
			}
			int num = 0;
			int num2 = -1;
			bool flag = false;
			for (int i = 0; i < json.Length; i++)
			{
				char c = json[i];
				if (flag)
				{
					switch (c)
					{
					case '\\':
						i++;
						break;
					case '"':
						flag = false;
						break;
					}
					continue;
				}
				switch (c)
				{
				case '"':
					flag = true;
					break;
				case '{':
					if (num == 0)
					{
						num2 = i;
					}
					num++;
					break;
				case '}':
					num--;
					if (num == 0 && num2 >= 0)
					{
						list.Add(json.Substring(num2, i - num2 + 1));
					}
					break;
				}
			}
			return list;
		}

		public static long AsLong(string s)
		{
			long result;
			if (!long.TryParse(s, out result))
			{
				return 0L;
			}
			return result;
		}

		public static bool AsBool(string s)
		{
			return string.Equals(s, "true", StringComparison.OrdinalIgnoreCase);
		}
	}
	internal static class TrayIcon
	{
		public static NotifyIcon Create(string text, EventHandler onShow, EventHandler onExit)
		{
			ContextMenuStrip contextMenuStrip = new ContextMenuStrip();
			ToolStripMenuItem toolStripMenuItem = new ToolStripMenuItem("显示主界面");
			toolStripMenuItem.Click += onShow;
			contextMenuStrip.Items.Add(toolStripMenuItem);
			contextMenuStrip.Items.Add(new ToolStripSeparator());
			ToolStripMenuItem toolStripMenuItem2 = new ToolStripMenuItem("退出");
			toolStripMenuItem2.Click += onExit;
			contextMenuStrip.Items.Add(toolStripMenuItem2);
			NotifyIcon notifyIcon = new NotifyIcon();
			try
			{
				notifyIcon.Icon = NetGateIcon.Create() ?? SystemIcons.Application;
			}
			catch
			{
				notifyIcon.Icon = SystemIcons.Application;
			}
			notifyIcon.Text = text;
			notifyIcon.Visible = true;
			notifyIcon.ContextMenuStrip = contextMenuStrip;
			notifyIcon.DoubleClick += onShow;
			return notifyIcon;
		}
	}
	internal class AdminConfig
	{
		public string Password = "";

		public string PasswordPlain = "";

		public string GatewayName = "";

		public int Port = 8899;

		public bool Enforce;

		public bool AutoAllow = true;

		public int AutoApproveMinutes;

		public Dictionary<string, long[]> Limits = new Dictionary<string, long[]>();

		public Dictionary<string, bool> Allowed = new Dictionary<string, bool>();

		// 被控制端禁言的设备（MAC → true），持久化在 admin.ini 的 mute.<mac>=1
		public Dictionary<string, bool> Muted = new Dictionary<string, bool>();

		public List<string> Names = new List<string>();

		private static string PathFile
		{
			get
			{
				return Path.Combine(Program.ProgramDataDir, "admin.ini");
			}
		}

		public static AdminConfig Load()
		{
			AdminConfig adminConfig = new AdminConfig();
			adminConfig.GatewayName = Environment.MachineName;
			try
			{
				if (!File.Exists(PathFile))
				{
					return adminConfig;
				}
				string[] array = File.ReadAllLines(PathFile, Encoding.UTF8);
				string[] array2 = array;
				foreach (string text in array2)
				{
					string text2 = text.Trim();
					if (text2.Length == 0 || text2.StartsWith("#"))
					{
						continue;
					}
					int num = text2.IndexOf('=');
					if (num <= 0)
					{
						continue;
					}
					string text3 = text2.Substring(0, num);
					string text4 = text2.Substring(num + 1);
					switch (text3)
					{
					case "password":
						adminConfig.Password = text4;
						continue;
					case "passwordplain":
						adminConfig.PasswordPlain = Unprotect(text4);
						continue;
					case "gatewayname":
						adminConfig.GatewayName = text4;
						continue;
					case "port":
						adminConfig.Port = (int)Util.AsLong(text4);
						continue;
					case "enforce":
						adminConfig.Enforce = text4 == "1";
						continue;
					case "autoallow":
						adminConfig.AutoAllow = text4 != "0";
						continue;
					case "autoapprove":
						adminConfig.AutoApproveMinutes = (int)Util.AsLong(text4);
						continue;
					}
					if (text3.StartsWith("limit."))
					{
						string key = text3.Substring(6);
						string[] array3 = text4.Split(':');
						adminConfig.Limits[key] = new long[2]
						{
							Util.AsLong(array3[0]),
							(array3.Length > 1) ? Util.AsLong(array3[1]) : 0
						};
					}
					else if (text3.StartsWith("allow."))
					{
						adminConfig.Allowed[text3.Substring(6)] = text4 == "1";
					}
					else if (text3.StartsWith("mute."))
					{
						adminConfig.Muted[text3.Substring(5)] = text4 == "1";
					}
					else if (text3.StartsWith("name."))
					{
						string text5 = text3.Substring(5);
						string text6 = Uri.UnescapeDataString(text4);
						int result;
						int.TryParse(text5.Substring(0, 1), out result);
						adminConfig.Names.Add(text5 + "\t" + text6);
					}
				}
				if (adminConfig.Port <= 0 || adminConfig.Port > 65535)
				{
					adminConfig.Port = 8899;
					return adminConfig;
				}
				return adminConfig;
			}
			catch
			{
				return adminConfig;
			}
		}

		public void Save()
		{
			try
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendLine("# NetGate admin config (do not edit while running)");
				stringBuilder.AppendLine("password=" + Password);
				stringBuilder.AppendLine("passwordplain=" + Protect(PasswordPlain));
				stringBuilder.AppendLine("gatewayname=" + (GatewayName ?? ""));
				stringBuilder.AppendLine("port=" + Port);
				stringBuilder.AppendLine("enforce=" + (Enforce ? "1" : "0"));
				stringBuilder.AppendLine("autoallow=" + (AutoAllow ? "1" : "0"));
				stringBuilder.AppendLine("autoapprove=" + AutoApproveMinutes);
				foreach (KeyValuePair<string, long[]> limit in Limits)
				{
					stringBuilder.AppendLine("limit." + limit.Key + "=" + limit.Value[0] + ":" + limit.Value[1]);
				}
				foreach (KeyValuePair<string, bool> item in Allowed)
				{
					stringBuilder.AppendLine("allow." + item.Key + "=" + (item.Value ? "1" : "0"));
				}
				foreach (KeyValuePair<string, bool> item in Muted)
				{
					stringBuilder.AppendLine("mute." + item.Key + "=" + (item.Value ? "1" : "0"));
				}
				foreach (string name in Names)
				{
					int num = name.IndexOf('\t');
					if (num > 0)
					{
						stringBuilder.AppendLine("name." + name.Substring(0, num) + "=" + Uri.EscapeDataString(name.Substring(num + 1)));
					}
				}
				File.WriteAllText(PathFile, stringBuilder.ToString(), new UTF8Encoding(false));
			}
			catch (Exception ex)
			{
				Program.Dbg("save config: " + ex.Message);
			}
		}

		private static string Protect(string s)
		{
			if (string.IsNullOrEmpty(s))
			{
				return "";
			}
			try
			{
				byte[] inArray = ProtectedData.Protect(Encoding.UTF8.GetBytes(s), null, DataProtectionScope.CurrentUser);
				return Convert.ToBase64String(inArray);
			}
			catch
			{
				return "";
			}
		}

		private static string Unprotect(string s)
		{
			if (string.IsNullOrEmpty(s))
			{
				return "";
			}
			try
			{
				byte[] bytes = ProtectedData.Unprotect(Convert.FromBase64String(s), null, DataProtectionScope.CurrentUser);
				return Encoding.UTF8.GetString(bytes);
			}
			catch
			{
				return "";
			}
		}

		public string GetName(string mac)
		{
			foreach (string name in Names)
			{
				int num = name.IndexOf('\t');
				if (num > 0 && name.Substring(0, num) == mac)
				{
					return name.Substring(num + 1);
				}
			}
			return null;
		}

		public void SetName(string mac, string name)
		{
			Names.RemoveAll((string x) => x.StartsWith(mac + "\t"));
			if (!string.IsNullOrEmpty(name))
			{
				Names.Add(mac + "\t" + name);
			}
		}
	}
	internal class ProxyResult
	{
		public bool Ok;

		public int Code;

		public string Key = "";

		public string Body = "";

		public string Error = "";

		public TcpClient Client;

		public NetworkStream Stream;
	}
	internal static class ProxyTalk
	{
		public static ProxyResult Connect(string ip, int port, string mac, string pwd, string target, string method, string extra, int timeoutMs)
		{
			ProxyResult proxyResult = new ProxyResult();
			TcpClient tcpClient = new TcpClient();
			try
			{
				IAsyncResult asyncResult = tcpClient.BeginConnect(ip, port, null, null);
				if (!asyncResult.AsyncWaitHandle.WaitOne(timeoutMs))
				{
					proxyResult.Error = "timeout";
					tcpClient.Close();
					return proxyResult;
				}
				tcpClient.EndConnect(asyncResult);
				tcpClient.NoDelay = true;
				NetworkStream stream = tcpClient.GetStream();
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(method).Append(' ').Append(target)
					.Append(" HTTP/1.1\r\n");
				stringBuilder.Append("Host: ").Append(target).Append("\r\n");
				stringBuilder.Append("User-Agent: NetGate/1.0\r\n");
				stringBuilder.Append("X-NetGate-Mac: ").Append(mac).Append("\r\n");
				if (!string.IsNullOrEmpty(pwd))
				{
					string value = Convert.ToBase64String(Encoding.UTF8.GetBytes("netgate:" + pwd));
					stringBuilder.Append("Proxy-Authorization: Basic ").Append(value).Append("\r\n");
				}
				if (!string.IsNullOrEmpty(extra))
				{
					stringBuilder.Append(extra);
				}
				stringBuilder.Append("Connection: close\r\n\r\n");
				byte[] bytes = Encoding.ASCII.GetBytes(stringBuilder.ToString());
				stream.Write(bytes, 0, bytes.Length);
				stream.Flush();
				tcpClient.ReceiveTimeout = timeoutMs;
				byte[] array = new byte[4096];
				int num = stream.Read(array, 0, array.Length);
				string text = ((num > 0) ? Encoding.UTF8.GetString(array, 0, num) : "");
				proxyResult.Code = 0;
				string[] array2 = text.Split('\n');
				if (array2.Length > 0)
				{
					string[] array3 = array2[0].Trim().Split(' ');
					if (array3.Length >= 2)
					{
						int.TryParse(array3[1], out proxyResult.Code);
					}
				}
				proxyResult.Key = Util.JsonField(text, "X-NetGate") ?? "";
				if (text.IndexOf("X-NetGate: ", StringComparison.Ordinal) >= 0)
				{
					int num2 = text.IndexOf("X-NetGate: ", StringComparison.Ordinal) + 11;
					int num3 = text.IndexOf('\r', num2);
					if (num3 > num2)
					{
						proxyResult.Key = text.Substring(num2, num3 - num2).Trim();
					}
				}
				int num4 = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
				if (num4 >= 0)
				{
					proxyResult.Body = text.Substring(num4 + 4);
				}
				proxyResult.Ok = proxyResult.Code >= 200 && proxyResult.Code < 300;
				proxyResult.Client = tcpClient;
				proxyResult.Stream = stream;
				return proxyResult;
			}
			catch (Exception ex)
			{
				proxyResult.Error = ex.Message;
				try
				{
					tcpClient.Close();
				}
				catch
				{
				}
				return proxyResult;
			}
		}

		public static string Status(string ip, int port, string mac, string name, string user, int timeoutMs)
		{
			string target = "/__netgate/hello?mac=" + mac + "&ip=" + Util.Q(Util.LanIPv4()) + "&name=" + Util.Q(name) + "&user=" + Util.Q(user) + "&v=1.0&nick=" + Util.Q(LocalNick());
			ProxyResult proxyResult = Connect(ip, port, mac, "", target, "GET", null, timeoutMs);
			try
			{
				if (proxyResult.Client != null)
				{
					proxyResult.Client.Close();
				}
			}
			catch
			{
			}
			if (!proxyResult.Ok)
			{
				return null;
			}
			return proxyResult.Body;
		}

		public static ProxyResult Verify(string ip, int port, string mac, string pwd, int timeoutMs)
		{
			string target = "/__netgate/auth?name=" + Util.Q(Environment.MachineName) + "&user=" + Util.Q(Environment.UserName) + "&ip=" + Util.Q(Util.LanIPv4()) + "&v=1.1&nick=" + Util.Q(LocalNick());
			return Connect(ip, port, mac, pwd, target, "GET", null, timeoutMs);
		}

		// 本机对外显示的名字（用户端可以在界面里改），控制端据此显示设备
		public static string LocalNick()
		{
			try
			{
				string text = FileTransferService.Current.LocalName;
				return string.IsNullOrEmpty(text) ? Environment.MachineName : text;
			}
			catch
			{
				return Environment.MachineName;
			}
		}
	}
	internal sealed class BetaWatermarkForm : Form
	{
		private readonly Form ownerForm;

		private Bitmap watermarkBitmap;

		private IntPtr memoryDc;

		private IntPtr bitmapHandle;

		private IntPtr oldBitmap;

		private Size bitmapSize;

		private System.Windows.Forms.Timer resizeTimer;

		public BetaWatermarkForm(Form owner)
		{
			ownerForm = owner;
			ShowInTaskbar = false;
			FormBorderStyle = FormBorderStyle.None;
			StartPosition = FormStartPosition.Manual;
			BackColor = Color.Black;
			SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
			base.Owner = owner;
			owner.Move += delegate
			{
				ScheduleUpdate();
			};
			owner.Resize += delegate
			{
				ScheduleUpdate();
			};
			owner.VisibleChanged += delegate
			{
				UpdateVisibility();
			};
			owner.Activated += delegate
			{
				UpdateVisibility();
			};
			owner.FormClosed += delegate
			{
				try
				{
					Close();
				}
				catch
				{
				}
			};
			resizeTimer = new System.Windows.Forms.Timer();
			resizeTimer.Interval = 80;
			resizeTimer.Tick += delegate
			{
				resizeTimer.Stop();
				UpdateLayer();
			};
		}

		protected override bool ShowWithoutActivation
		{
			get
			{
				return true;
			}
		}

		protected override CreateParams CreateParams
		{
			get
			{
				CreateParams createParams = base.CreateParams;
				createParams.ExStyle |= 0x80000;
				createParams.ExStyle |= 0x20;
				createParams.ExStyle |= 0x8000000;
				createParams.ExStyle |= 0x80;
				return createParams;
			}
		}

		public void UpdateVisibility()
		{
			try
			{
				if (ownerForm == null || ownerForm.IsDisposed || !ownerForm.Visible || ownerForm.WindowState == FormWindowState.Minimized)
				{
					Hide();
					return;
				}
				UpdateLayer();
			}
			catch
			{
			}
		}

		private void ScheduleUpdate()
		{
			try
			{
				if (resizeTimer != null)
				{
					resizeTimer.Stop();
					resizeTimer.Start();
				}
			}
			catch
			{
			}
		}

		private void UpdateLayer()
		{
			try
			{
				if (ownerForm == null || ownerForm.IsDisposed || !ownerForm.Visible || ownerForm.WindowState == FormWindowState.Minimized)
				{
					Hide();
					return;
				}
				Rectangle rectangle = ownerForm.RectangleToScreen(ownerForm.ClientRectangle);
				if (rectangle.Width <= 0 || rectangle.Height <= 0)
				{
					return;
				}
				if (watermarkBitmap == null || bitmapSize.Width != rectangle.Width || bitmapSize.Height != rectangle.Height)
				{
					ReleaseBitmap();
					watermarkBitmap = new Bitmap(rectangle.Width, rectangle.Height, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
					using (Graphics graphics = Graphics.FromImage(watermarkBitmap))
					{
						graphics.Clear(Color.Transparent);
						DrawWatermark(graphics, rectangle.Width, rectangle.Height);
					}
					IntPtr dcc = GetDC(IntPtr.Zero);
					memoryDc = CreateCompatibleDC(dcc);
					bitmapHandle = watermarkBitmap.GetHbitmap(Color.FromArgb(0));
					oldBitmap = SelectObject(memoryDc, bitmapHandle);
					ReleaseDC(IntPtr.Zero, dcc);
					bitmapSize = rectangle.Size;
				}
				IntPtr dcc2 = GetDC(IntPtr.Zero);
				POINT pointDst = new POINT();
				pointDst.X = rectangle.Left;
				pointDst.Y = rectangle.Top;
				POINT pointSrc = new POINT();
				SIZE size = new SIZE();
				size.cx = rectangle.Width;
				size.cy = rectangle.Height;
				BLENDFUNCTION blend = new BLENDFUNCTION();
				blend.BlendOp = 0;
				blend.BlendFlags = 0;
				blend.SourceConstantAlpha = 255;
				blend.AlphaFormat = 1;
				UpdateLayeredWindow(Handle, dcc2, ref pointDst, ref size, memoryDc, ref pointSrc, 0, ref blend, 2);
				ReleaseDC(IntPtr.Zero, dcc2);
				if (!Visible)
				{
					Show();
				}
			}
			catch
			{
			}
		}

		private static void DrawWatermark(Graphics graphics, int width, int height)
		{
			if (width < 320 || height < 220)
			{
				return;
			}
			float num = Math.Min(56f, Math.Max(28f, Math.Min(width, height) / 14f));
			graphics.SmoothingMode = SmoothingMode.AntiAlias;
			graphics.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
			graphics.TranslateTransform(width / 2f, height / 2f);
			graphics.RotateTransform(-24f);
			using (StringFormat format = new StringFormat())
			{
				format.Alignment = StringAlignment.Center;
				format.LineAlignment = StringAlignment.Center;
				float num2 = Math.Max(400f, num * 7.4f);
				float num3 = Math.Max(260f, num * 4.8f);
				float num4 = (float)Math.Sqrt(width * width + height * height);
				int num5 = (int)(num4 / (num2 * 2f)) + 2;
				int num6 = (int)(num4 / (num3 * 2f)) + 2;
				using (SolidBrush brush = new SolidBrush(Color.FromArgb(58, 200, 30, 30)))
				{
					using (Font font = new Font("Microsoft YaHei UI", num, FontStyle.Bold))
					{
						using (Font font2 = new Font("Microsoft YaHei UI", Math.Max(15f, num / 3.2f), FontStyle.Bold))
						{
							for (int i = -num6; i <= num6; i++)
							{
								float num7 = (((i & 1) == 0) ? 0f : (num2 / 2f));
								float num8 = i * num3;
								for (int j = -num5; j <= num5; j++)
								{
									float num9 = j * num2 + num7;
									graphics.DrawString("BETA", font, brush, num9, num8 - num * 0.55f, format);
									if (i == 0 && j == 0)
									{
										graphics.DrawString("BUILD " + UiKit.BuildTime, font2, brush, num9, num8 + num * 0.42f, format);
										graphics.DrawString("by YanzheQu", font2, brush, num9, num8 + num * 1.08f, format);
									}
								}
							}
						}
					}
				}
			}
		}

		private void ReleaseBitmap()
		{
			try
			{
				if (memoryDc != IntPtr.Zero)
				{
					if (oldBitmap != IntPtr.Zero)
					{
						SelectObject(memoryDc, oldBitmap);
					}
					if (bitmapHandle != IntPtr.Zero)
					{
						DeleteObject(bitmapHandle);
					}
					DeleteDC(memoryDc);
				}
			}
			catch
			{
			}
			memoryDc = IntPtr.Zero;
			bitmapHandle = IntPtr.Zero;
			oldBitmap = IntPtr.Zero;
			if (watermarkBitmap != null)
			{
				watermarkBitmap.Dispose();
				watermarkBitmap = null;
			}
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (resizeTimer != null)
				{
					resizeTimer.Stop();
					resizeTimer.Dispose();
					resizeTimer = null;
				}
			}
			catch
			{
			}
			ReleaseBitmap();
			base.Dispose(disposing);
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct POINT
		{
			public int X;

			public int Y;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct SIZE
		{
			public int cx;

			public int cy;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		private struct BLENDFUNCTION
		{
			public byte BlendOp;

			public byte BlendFlags;

			public byte SourceConstantAlpha;

			public byte AlphaFormat;
		}

		[DllImport("user32.dll", SetLastError = true)]
		private static extern bool UpdateLayeredWindow(IntPtr hwnd, IntPtr hdcDst, ref POINT pptDst, ref SIZE psize, IntPtr hdcSrc, ref POINT pptSrc, int crKey, ref BLENDFUNCTION pblend, int dwFlags);

		[DllImport("user32.dll")]
		private static extern IntPtr GetDC(IntPtr hWnd);

		[DllImport("user32.dll")]
		private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

		[DllImport("gdi32.dll")]
		private static extern IntPtr CreateCompatibleDC(IntPtr hdc);

		[DllImport("gdi32.dll")]
		private static extern IntPtr SelectObject(IntPtr hdc, IntPtr hObj);

		[DllImport("gdi32.dll")]
		private static extern bool DeleteObject(IntPtr hObj);

		[DllImport("gdi32.dll")]
		private static extern bool DeleteDC(IntPtr hdc);
	}
	internal static class UiKit
	{
		public static readonly Color Bg = Color.FromArgb(243, 245, 248);

		public static readonly Color Card = Color.White;

		public static readonly Color Border = Color.FromArgb(226, 232, 240);

		public static readonly Color TextColor = Color.FromArgb(15, 23, 42);

		public static readonly Color Muted = Color.FromArgb(100, 116, 139);

		public static readonly Color Primary = Color.FromArgb(37, 99, 235);

		public static readonly Color PrimaryDark = Color.FromArgb(29, 78, 216);

		public static readonly Color Header = Color.FromArgb(15, 23, 42);

		public static readonly Color HeaderText = Color.FromArgb(148, 163, 184);

		public static readonly Color Success = Color.FromArgb(22, 163, 74);

		public static readonly Color Danger = Color.FromArgb(220, 38, 38);

		public static readonly Font Body = new Font("Microsoft YaHei UI", 9.5f);

		public static readonly Font BodyBold = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold);

		public static readonly Font Value = new Font("Consolas", 20f, FontStyle.Bold);

		public static readonly Font Password = new Font("Consolas", 15f, FontStyle.Bold);

		public static readonly Font Mono = new Font("Consolas", 9.5f);

		public static readonly Font Title = new Font("Microsoft YaHei UI", 16f, FontStyle.Bold);

		public static readonly Font SubTitle = new Font("Microsoft YaHei UI", 11f, FontStyle.Bold);

		public static readonly string BuildTime = GetBuildTime();

		private static string GetBuildTime()
		{
			try
			{
				string text = typeof(UiKit).Assembly.Location;
				if (string.IsNullOrEmpty(text) || !File.Exists(text))
				{
					text = Application.ExecutablePath;
				}
				return File.GetLastWriteTime(text).ToString("yyyy-MM-dd HH:mm:ss");
			}
			catch
			{
				return "unknown";
			}
		}

		public static void AddBetaWatermark(Form form)
		{
			try
			{
				BetaWatermarkForm overlay = new BetaWatermarkForm(form);
				form.Shown += delegate
				{
					overlay.UpdateVisibility();
				};
			}
			catch
			{
			}
		}

		[DllImport("user32.dll", CharSet = CharSet.Unicode)]
		private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

		public static void Apply(Form form)
		{
			form.BackColor = Bg;
			form.Font = Body;
			form.AutoScaleMode = AutoScaleMode.None;
			try
			{
				form.Icon = NetGateIcon.Create();
			}
			catch
			{
			}
		}

		public static Panel CardPanel()
		{
			Panel panel = new Panel();
			panel.BackColor = Card;
			panel.Paint += delegate(object s, PaintEventArgs e)
			{
				Control control = s as Control;
				if (control != null)
				{
					using (Pen pen = new Pen(Border))
					{
						e.Graphics.DrawRectangle(pen, 0, 0, control.Width - 1, control.Height - 1);
					}
				}
			};
			return panel;
		}

		public static Label FieldLabel(string text)
		{
			return new Label
			{
				Text = text,
				AutoSize = true,
				ForeColor = Muted,
				Font = Body,
				Margin = new Padding(0)
			};
		}

		public static Button PrimaryButton(string text)
		{
			return MakeButton(text, true, 34);
		}

		public static Button SecondaryButton(string text)
		{
			return MakeButton(text, false, 34);
		}

		public static Button ToolButton(string text, bool primary)
		{
			return MakeButton(text, primary, 34);
		}

		private static Button MakeButton(string text, bool primary, int height)
		{
			Button button = new Button();
			button.Text = text;
			button.Height = height;
			button.AutoSize = false;
			button.Width = TextRenderer.MeasureText(text, primary ? BodyBold : Body).Width + 26;
			button.FlatStyle = FlatStyle.Flat;
			button.Cursor = Cursors.Hand;
			button.Font = (primary ? BodyBold : Body);
			button.FlatAppearance.BorderSize = (primary ? 0 : 1);
			button.FlatAppearance.BorderColor = Border;
			button.FlatAppearance.MouseOverBackColor = (primary ? PrimaryDark : Color.FromArgb(248, 250, 252));
			button.FlatAppearance.MouseDownBackColor = (primary ? Color.FromArgb(30, 64, 175) : Color.FromArgb(241, 245, 249));
			button.BackColor = (primary ? Primary : Card);
			button.ForeColor = (primary ? Color.White : TextColor);
			button.Margin = new Padding(0, 0, 8, 0);
			button.UseVisualStyleBackColor = false;
			return button;
		}

		public static void StyleGrid(DataGridView grid)
		{
			grid.BackgroundColor = Card;
			grid.BorderStyle = BorderStyle.None;
			grid.GridColor = Color.FromArgb(241, 245, 249);
			grid.EnableHeadersVisualStyles = false;
			grid.RowHeadersVisible = false;
			grid.AllowUserToAddRows = false;
			grid.AllowUserToDeleteRows = false;
			grid.AllowUserToResizeRows = false;
			grid.ReadOnly = true;
			grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
			grid.MultiSelect = false;
			grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
			grid.ColumnHeadersHeight = 38;
			grid.RowTemplate.Height = 36;
			grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
			grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(248, 250, 252);
			grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(71, 85, 105);
			grid.ColumnHeadersDefaultCellStyle.Font = BodyBold;
			grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(8, 0, 8, 0);
			grid.ColumnHeadersDefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleLeft;
			grid.DefaultCellStyle.Font = Body;
			grid.DefaultCellStyle.BackColor = Card;
			grid.DefaultCellStyle.ForeColor = TextColor;
			grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(219, 234, 254);
			grid.DefaultCellStyle.SelectionForeColor = TextColor;
			grid.DefaultCellStyle.Padding = new Padding(8, 0, 8, 0);
			grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(250, 251, 253);
			DoubleBuffer(grid);
		}

		public static void StyleList(ListView list)
		{
			list.BorderStyle = BorderStyle.FixedSingle;
			list.BackColor = Card;
			list.ForeColor = TextColor;
			list.Font = Body;
			list.FullRowSelect = true;
			list.HideSelection = false;
			list.HeaderStyle = ColumnHeaderStyle.Nonclickable;
			DoubleBuffer(list);
		}

		public static Panel StatusBar(Label label)
		{
			Panel panel = new Panel();
			panel.Dock = DockStyle.Fill;
			panel.BackColor = Card;
			panel.Paint += delegate(object s, PaintEventArgs e)
			{
				Control control = s as Control;
				if (control != null)
				{
					using (Pen pen = new Pen(Border))
					{
						e.Graphics.DrawLine(pen, 0, 0, control.Width, 0);
					}
				}
			};
			label.Dock = DockStyle.Fill;
			label.AutoSize = false;
			label.TextAlign = ContentAlignment.MiddleLeft;
			label.ForeColor = Muted;
			label.Font = Body;
			label.Padding = new Padding(20, 0, 20, 0);
			panel.Controls.Add(label);
			return panel;
		}

		public static void SetPlaceholder(TextBox box, string text)
		{
			try
			{
				SendMessage(box.Handle, 0x1501, IntPtr.Zero, text);
			}
			catch
			{
			}
		}

		public static void DoubleBuffer(Control control)
		{
			try
			{
				PropertyInfo property = typeof(Control).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic);
				if (property != null)
				{
					property.SetValue(control, true, null);
				}
			}
			catch
			{
			}
		}
	}
	internal class AdminForm : Form
	{
		private class DeviceView
		{
			public string Mac;

			public string Name;

			public string Nick;

			public string Ip;

			public string User;

			public bool Online;

			public bool Allowed;

			public bool Pending;

			public bool Paused;

			public bool ChatMuted;

			public long Up;

			public long Down;

			public long CurUp;

			public long CurDown;

			public long LimitUp;

			public long LimitDown;

			public DateTime Last = DateTime.Now;
		}

		private AdminConfig cfg;

		private NetGateServer server;

		private DataGridView grid;

		private Label lblAddr;

		private Label lblStatus;

		private Label lblInfo;

		private TextBox logBox;

		private TextBox txtPwd;

		private Button btnPwd;

		private Button btnAllow;

		private Button btnDeny;

		private Button btnPause;

		private Button btnSpeed;

		private Button btnRefresh;

		private Button btnFiles;

		private Button btnChat;

		private Button btnName;

		private Button btnFirewall;

		private Button btnCopyAddr;

		private Button btnOpenLog;

		private CheckBox chkAutoAllow;

		private CheckBox chkShowPwd;

		private System.Windows.Forms.Timer timer;

		private List<DeviceView> rows = new List<DeviceView>();

		private bool closing;

		private bool allowExit;

		private NotifyIcon tray;

		private int testStart;

		private HashSet<string> pendingShown = new HashSet<string>();

		public AdminForm(AdminConfig c, bool firstRun)
		{
			AdminForm adminForm = this;
			cfg = c;
			Text = "NetGate 控制端";
			base.Size = new Size(1000, 680);
			MinimumSize = new Size(960, 620);
			base.StartPosition = FormStartPosition.CenterScreen;
			Font = new Font("Microsoft YaHei UI", 9f);
			base.AutoScaleMode = AutoScaleMode.None;
			base.Icon = NetGateIcon.Create();
			BuildUiModern();
			UiKit.AddBetaWatermark(this);
			FileTransferService.UiOwner = this;
			if (!Program.SelfTest)
			{
				tray = TrayIcon.Create("NetGate 控制端（代理运行中）", delegate
				{
					RestoreWindow();
				}, delegate
				{
					ExitApp();
				});
			}
			base.Load += delegate
			{
				adminForm.StartEngine();
				adminForm.EnsurePassword(firstRun);
				adminForm.RefreshAll();
			};
			// 收到聊天消息：聊天窗口没开就弹托盘气泡并记一条日志
			FileTransferService.ChatArrived += delegate(ChatMessage m)
			{
				try
				{
					if (ChatForm.IsOpen || adminForm.IsDisposed)
					{
						return;
					}
					adminForm.BeginInvoke((MethodInvoker)delegate
					{
						try
						{
							if (ChatForm.IsOpen)
							{
								return;
							}
							if (tray != null)
							{
								tray.ShowBalloonTip(2500, "NetGate 局域网消息", m.FromName + "：" + m.Text, ToolTipIcon.Info);
							}
							AppendLog("收到 " + m.FromName + "（" + m.FromIp + "）的消息：" + m.Text);
						}
						catch
						{
						}
					});
				}
				catch
				{
				}
			};
			base.FormClosing += delegate(object s, FormClosingEventArgs e)
			{
				if (!allowExit && !Program.SelfTest && (e.CloseReason == CloseReason.UserClosing || e.CloseReason == CloseReason.TaskManagerClosing))
				{
					e.Cancel = true;
					Hide();
					if (tray != null)
					{
						tray.ShowBalloonTip(1500, "NetGate 控制端", "已最小化到托盘，代理服务继续运行。\r\n退出请右键托盘图标。", ToolTipIcon.Info);
					}
				}
				else
				{
					closing = true;
					if (timer != null)
					{
						timer.Stop();
					}
				}
			};
			base.FormClosed += delegate
			{
				Shutdown();
				try
				{
					if (tray != null)
					{
						tray.Visible = false;
						tray.Dispose();
						tray = null;
					}
				}
				catch
				{
				}
			};
		}

		private void BuildUiOld()
		{
			Panel panel = new Panel();
			panel.Dock = DockStyle.Top;
			panel.Height = 74;
			panel.BackColor = Color.FromArgb(15, 23, 42);
			Panel panel2 = panel;
			base.Controls.Add(panel2);
			panel2.Controls.Add(new Label
			{
				Text = "NetGate 控制端",
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 15f, FontStyle.Bold),
				Location = new Point(16, 8),
				AutoSize = true
			});
			lblAddr = new Label
			{
				Text = "",
				ForeColor = Color.FromArgb(56, 189, 248),
				Font = new Font("Consolas", 13f, FontStyle.Bold),
				Location = new Point(300, 10),
				AutoSize = true
			};
			panel2.Controls.Add(lblAddr);
			lblStatus = new Label
			{
				Text = "正在启动…",
				ForeColor = Color.FromArgb(148, 163, 184),
				Location = new Point(300, 42),
				AutoSize = true
			};
			panel2.Controls.Add(lblStatus);
			Label label = new Label();
			label.Text = "用户端填写上面的地址 + 授权密码即可通过这台电脑上网";
			label.ForeColor = Color.FromArgb(148, 163, 184);
			label.Location = new Point(16, 46);
			label.AutoSize = true;
			Label value = label;
			panel2.Controls.Add(value);
			Panel panel3 = new Panel();
			panel3.Dock = DockStyle.Right;
			panel3.Width = 200;
			panel3.BackColor = Color.FromArgb(248, 250, 252);
			panel3.Padding = new Padding(8);
			panel3.AutoScroll = true;
			Panel panel4 = panel3;
			base.Controls.Add(panel4);
			int num = 6;
			btnPwd = MakeButton(panel4, "修改授权密码", ref num, 34);
			btnAllow = MakeButton(panel4, "允许上网", ref num, 32);
			btnDeny = MakeButton(panel4, "断开 / 禁止", ref num, 32);
			btnPause = MakeButton(panel4, "暂停 / 恢复", ref num, 30);
			btnSpeed = MakeButton(panel4, "限速设置…", ref num, 32);
			btnRefresh = MakeButton(panel4, "刷新", ref num, 28);
			btnFiles = MakeButton(panel4, "文件传输…", ref num, 32);
			btnFirewall = MakeButton(panel4, "开放防火墙端口", ref num, 28);
			btnCopyAddr = MakeButton(panel4, "复制网关地址", ref num, 28);
			btnOpenLog = MakeButton(panel4, "打开日志", ref num, 28);
			lblInfo = new Label
			{
				Location = new Point(10, num + 6),
				Size = new Size(178, 150),
				ForeColor = Color.FromArgb(71, 85, 105)
			};
			panel4.Controls.Add(lblInfo);
			logBox = new TextBox
			{
				Multiline = true,
				ReadOnly = true,
				ScrollBars = ScrollBars.Vertical,
				Dock = DockStyle.Bottom,
				Height = 110,
				BackColor = Color.FromArgb(248, 250, 252),
				Font = new Font("Consolas", 9f)
			};
			base.Controls.Add(logBox);
			grid = new DataGridView
			{
				Dock = DockStyle.Fill,
				ReadOnly = true,
				AllowUserToAddRows = false,
				AllowUserToDeleteRows = false,
				AllowUserToResizeRows = false,
				RowHeadersVisible = false,
				SelectionMode = DataGridViewSelectionMode.FullRowSelect,
				MultiSelect = false,
				AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
				BackgroundColor = Color.White,
				BorderStyle = BorderStyle.None,
				GridColor = Color.FromArgb(226, 232, 240),
				EnableHeadersVisualStyles = false
			};
			grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(241, 245, 249);
			string[][] array = new string[8][]
			{
				new string[2] { "status", "状态" },
				new string[2] { "nick", "自定义名称" },
				new string[2] { "name", "计算机名" },
				new string[2] { "ip", "IP 地址" },
				new string[2] { "limit", "限速" },
				new string[2] { "rate", "当前速度" },
				new string[2] { "total", "累计流量" },
				new string[2] { "last", "最近在线" }
			};
			foreach (string[] array2 in array)
			{
				DataGridViewTextBoxColumn dataGridViewTextBoxColumn = new DataGridViewTextBoxColumn();
				dataGridViewTextBoxColumn.Name = array2[0];
				dataGridViewTextBoxColumn.HeaderText = array2[1];
				dataGridViewTextBoxColumn.SortMode = DataGridViewColumnSortMode.NotSortable;
				if (array2[0] == "nick")
				{
					dataGridViewTextBoxColumn.FillWeight = 150f;
				}
				else if (array2[0] == "name")
				{
					dataGridViewTextBoxColumn.FillWeight = 120f;
				}
				else if (array2[0] == "status")
				{
					dataGridViewTextBoxColumn.FillWeight = 70f;
				}
				else if (array2[0] == "ip")
				{
					dataGridViewTextBoxColumn.FillWeight = 100f;
				}
				else if (array2[0] == "rate")
				{
					dataGridViewTextBoxColumn.FillWeight = 120f;
				}
				else if (array2[0] == "total")
				{
					dataGridViewTextBoxColumn.FillWeight = 130f;
				}
				grid.Columns.Add(dataGridViewTextBoxColumn);
			}
			base.Controls.Add(grid);
			grid.BringToFront();
			btnPwd.Click += delegate
			{
				ChangePassword();
			};
			btnAllow.Click += delegate
			{
				AllowSelected(true);
			};
			btnDeny.Click += delegate
			{
				AllowSelected(false);
			};
			btnPause.Click += delegate
			{
				PauseSelected();
			};
			btnSpeed.Click += delegate
			{
				SpeedDialog();
			};
			btnRefresh.Click += delegate
			{
				RefreshAll();
			};
			btnFiles.Click += delegate
			{
				FileTransferForm.ShowShared(this);
			};
			btnFirewall.Click += delegate
			{
				bool flag = Firewall.OpenPorts(FirewallPorts());
				AppendLog(flag ? ("已开放防火墙端口：代理 " + cfg.Port + "，文件传输 8895-8905") : "开放防火墙端口失败（需要管理员权限）。");
			};
			btnCopyAddr.Click += delegate
			{
				try
				{
					Clipboard.SetText(Util.LanIPv4() + ":" + cfg.Port);
					AppendLog("网关地址已复制：" + Util.LanIPv4() + ":" + cfg.Port);
				}
				catch
				{
				}
			};
			btnOpenLog.Click += delegate
			{
				try
				{
					Process.Start("notepad.exe", NetGateServer.LogPath);
				}
				catch
				{
				}
			};
			grid.CellDoubleClick += delegate(object s, DataGridViewCellEventArgs e)
			{
				if (e.RowIndex >= 0)
				{
					SpeedDialog();
				}
			};
			timer = new System.Windows.Forms.Timer
			{
				Interval = 1000
			};
			timer.Tick += delegate
			{
				if (!closing)
				{
					RefreshAll();
				}
				if (Program.SelfTest && Environment.TickCount - testStart > 3000 && !Program.SelfTestDone)
				{
					Program.SelfTestDone = true;
					Program.Dbg("SELFTEST-OK");
					Close();
				}
			};
			testStart = Environment.TickCount;
			timer.Start();
		}

		private static Button MakeButton(Control parent, string text, ref int y, int h)
		{
			Button button = new Button();
			button.Text = text;
			button.Location = new Point(10, y);
			button.Size = new Size(178, h);
			button.FlatStyle = FlatStyle.System;
			Button button2 = button;
			parent.Controls.Add(button2);
			y += h + 6;
			return button2;
		}

		private void BuildUi()
		{
			TableLayoutPanel tableLayoutPanel = new TableLayoutPanel();
			tableLayoutPanel.Dock = DockStyle.Fill;
			tableLayoutPanel.ColumnCount = 1;
			tableLayoutPanel.RowCount = 5;
			tableLayoutPanel.BackColor = Color.White;
			TableLayoutPanel tableLayoutPanel2 = tableLayoutPanel;
			tableLayoutPanel2.RowStyles.Add(new RowStyle(SizeType.Absolute, 64f));
			tableLayoutPanel2.RowStyles.Add(new RowStyle(SizeType.Absolute, 156f));
			tableLayoutPanel2.RowStyles.Add(new RowStyle(SizeType.Absolute, 54f));
			tableLayoutPanel2.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			tableLayoutPanel2.RowStyles.Add(new RowStyle(SizeType.Absolute, 96f));
			base.Controls.Add(tableLayoutPanel2);
			Panel panel = new Panel();
			panel.Dock = DockStyle.Fill;
			panel.BackColor = Color.FromArgb(15, 23, 42);
			Panel panel2 = panel;
			tableLayoutPanel2.Controls.Add(panel2, 0, 0);
			panel2.Controls.Add(new Label
			{
				Text = "NetGate 控制端",
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 15f, FontStyle.Bold),
				Location = new Point(18, 8),
				AutoSize = true
			});
			panel2.Controls.Add(new Label
			{
				Text = "让局域网里的电脑通过本机上网",
				ForeColor = Color.FromArgb(148, 163, 184),
				Location = new Point(250, 15),
				AutoSize = true
			});
			lblStatus = new Label
			{
				Text = "正在启动…",
				ForeColor = Color.FromArgb(148, 163, 184),
				Location = new Point(18, 38),
				AutoSize = true
			};
			panel2.Controls.Add(lblStatus);
			panel2.Controls.Add(new Label
			{
				Text = "关闭窗口 = 收起到托盘继续运行",
				ForeColor = Color.FromArgb(100, 116, 139),
				Location = new Point(760, 20),
				AutoSize = true
			});
			Panel panel3 = new Panel();
			panel3.Dock = DockStyle.Fill;
			panel3.BackColor = Color.White;
			panel3.Padding = new Padding(18, 6, 18, 6);
			Panel panel4 = panel3;
			tableLayoutPanel2.Controls.Add(panel4, 0, 1);
			panel4.Controls.Add(new Label
			{
				Text = "① 连接信息（把地址和密码告诉要上网的电脑）",
				ForeColor = Color.FromArgb(30, 41, 59),
				Font = new Font("Microsoft YaHei UI", 10.5f, FontStyle.Bold),
				Location = new Point(18, 6),
				AutoSize = true
			});
			lblAddr = new Label
			{
				Text = "正在获取本机地址…",
				ForeColor = Color.FromArgb(37, 99, 235),
				Font = new Font("Consolas", 21f, FontStyle.Bold),
				Location = new Point(18, 32),
				AutoSize = true
			};
			panel4.Controls.Add(lblAddr);
			panel4.Controls.Add(new Label
			{
				Text = "密码",
				ForeColor = Color.FromArgb(71, 85, 105),
				Location = new Point(20, 84),
				AutoSize = true
			});
			txtPwd = new TextBox
			{
				Location = new Point(76, 78),
				Size = new Size(210, 34),
				Font = new Font("Consolas", 16f, FontStyle.Bold),
				ReadOnly = true,
				BorderStyle = BorderStyle.FixedSingle,
				TextAlign = HorizontalAlignment.Left,
				BackColor = Color.White,
				ForeColor = Color.FromArgb(15, 23, 42)
			};
			panel4.Controls.Add(txtPwd);
			chkShowPwd = new CheckBox
			{
				Text = "显示",
				Location = new Point(294, 84),
				Size = new Size(62, 22),
				ForeColor = Color.FromArgb(71, 85, 105)
			};
			panel4.Controls.Add(chkShowPwd);
			btnCopyAddr = new Button
			{
				Text = "复制连接信息",
				Location = new Point(370, 74),
				Size = new Size(168, 40),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.FromArgb(37, 99, 235),
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 10f, FontStyle.Bold)
			};
			btnCopyAddr.FlatAppearance.BorderSize = 0;
			panel4.Controls.Add(btnCopyAddr);
			btnPwd = new Button
			{
				Text = "换密码",
				Location = new Point(548, 74),
				Size = new Size(100, 40),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.White,
				ForeColor = Color.FromArgb(30, 41, 59)
			};
			btnPwd.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
			panel4.Controls.Add(btnPwd);
			btnChat = new Button
			{
				Text = "局域网群聊…",
				Location = new Point(660, 74),
				Size = new Size(130, 40),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.White,
				ForeColor = Color.FromArgb(30, 41, 59),
				Font = new Font("Microsoft YaHei UI", 9f)
			};
			btnChat.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
			panel4.Controls.Add(btnChat);
			btnName = new Button
			{
				Text = "我的名称…",
				Location = new Point(798, 74),
				Size = new Size(110, 40),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.White,
				ForeColor = Color.FromArgb(30, 41, 59),
				Font = new Font("Microsoft YaHei UI", 9f)
			};
			btnName.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
			panel4.Controls.Add(btnName);
			lblInfo = new Label
			{
				Location = new Point(18, 124),
				Size = new Size(960, 22),
				ForeColor = Color.FromArgb(100, 116, 139)
			};
			panel4.Controls.Add(lblInfo);
			FlowLayoutPanel flowLayoutPanel = new FlowLayoutPanel();
			flowLayoutPanel.Dock = DockStyle.Fill;
			flowLayoutPanel.FlowDirection = FlowDirection.LeftToRight;
			flowLayoutPanel.WrapContents = false;
			flowLayoutPanel.BackColor = Color.FromArgb(248, 250, 252);
			flowLayoutPanel.Padding = new Padding(12, 4, 12, 4);
			FlowLayoutPanel flowLayoutPanel2 = flowLayoutPanel;
			tableLayoutPanel2.Controls.Add(flowLayoutPanel2, 0, 2);
			chkAutoAllow = new CheckBox
			{
				Text = "新设备自动允许上网",
				AutoSize = true,
				Checked = cfg.AutoAllow,
				ForeColor = Color.FromArgb(30, 41, 59),
				Margin = new Padding(4, 10, 18, 0)
			};
			flowLayoutPanel2.Controls.Add(chkAutoAllow);
			btnAllow = BarButton(flowLayoutPanel2, "允许上网", 96, true);
			btnDeny = BarButton(flowLayoutPanel2, "断开 / 禁止", 104, false);
			btnPause = BarButton(flowLayoutPanel2, "暂停 / 恢复", 104, false);
			btnSpeed = BarButton(flowLayoutPanel2, "限速设置…", 104, false);
			btnFiles = BarButton(flowLayoutPanel2, "文件传输…", 104, false);
			btnRefresh = BarButton(flowLayoutPanel2, "刷新", 70, false);
			btnFirewall = BarButton(flowLayoutPanel2, "防火墙", 80, false);
			btnOpenLog = BarButton(flowLayoutPanel2, "日志", 70, false);
			logBox = new TextBox
			{
				Dock = DockStyle.Fill,
				Multiline = true,
				ReadOnly = true,
				ScrollBars = ScrollBars.Vertical,
				BackColor = Color.FromArgb(248, 250, 252),
				BorderStyle = BorderStyle.None,
				Font = new Font("Consolas", 8.5f)
			};
			tableLayoutPanel2.Controls.Add(logBox, 0, 4);
			grid = new DataGridView
			{
				Dock = DockStyle.Fill,
				ReadOnly = true,
				AllowUserToAddRows = false,
				AllowUserToDeleteRows = false,
				AllowUserToResizeRows = false,
				RowHeadersVisible = false,
				SelectionMode = DataGridViewSelectionMode.FullRowSelect,
				MultiSelect = false,
				AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
				BackgroundColor = Color.White,
				BorderStyle = BorderStyle.None,
				GridColor = Color.FromArgb(226, 232, 240),
				EnableHeadersVisualStyles = false,
				ColumnHeadersHeight = 36,
				RowTemplate = 
				{
					Height = 30
				}
			};
			grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(241, 245, 249);
			grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(51, 65, 85);
			grid.DefaultCellStyle.Font = new Font("Microsoft YaHei UI", 9f);
			grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(219, 234, 254);
			grid.DefaultCellStyle.SelectionForeColor = Color.FromArgb(15, 23, 42);
			string[][] array = new string[8][]
			{
				new string[2] { "status", "状态" },
				new string[2] { "nick", "自定义名称" },
				new string[2] { "name", "计算机名" },
				new string[2] { "ip", "IP 地址" },
				new string[2] { "limit", "限速" },
				new string[2] { "rate", "当前速度" },
				new string[2] { "total", "累计流量" },
				new string[2] { "last", "最近在线" }
			};
			foreach (string[] array2 in array)
			{
				DataGridViewTextBoxColumn dataGridViewTextBoxColumn = new DataGridViewTextBoxColumn();
				dataGridViewTextBoxColumn.Name = array2[0];
				dataGridViewTextBoxColumn.HeaderText = array2[1];
				dataGridViewTextBoxColumn.SortMode = DataGridViewColumnSortMode.NotSortable;
				if (array2[0] == "nick")
				{
					dataGridViewTextBoxColumn.FillWeight = 150f;
				}
				else if (array2[0] == "name")
				{
					dataGridViewTextBoxColumn.FillWeight = 130f;
				}
				else if (array2[0] == "status")
				{
					dataGridViewTextBoxColumn.FillWeight = 80f;
				}
				else if (array2[0] == "ip")
				{
					dataGridViewTextBoxColumn.FillWeight = 110f;
				}
				else if (array2[0] == "rate")
				{
					dataGridViewTextBoxColumn.FillWeight = 120f;
				}
				else if (array2[0] == "total")
				{
					dataGridViewTextBoxColumn.FillWeight = 130f;
				}
				grid.Columns.Add(dataGridViewTextBoxColumn);
			}
			tableLayoutPanel2.Controls.Add(grid, 0, 3);
			btnPwd.Click += delegate
			{
				ChangePassword();
			};
			btnAllow.Click += delegate
			{
				AllowSelected(true);
			};
			btnDeny.Click += delegate
			{
				AllowSelected(false);
			};
			btnPause.Click += delegate
			{
				PauseSelected();
			};
			btnSpeed.Click += delegate
			{
				SpeedDialog();
			};
			btnRefresh.Click += delegate
			{
				RefreshAll();
			};
			btnFiles.Click += delegate
			{
				HubForm.ShowShared(this, server, cfg, 1);
			};
			btnChat.Click += delegate
			{
				HubForm.ShowShared(this, server, cfg, 0);
			};
			btnName.Click += delegate
			{
				ChangeMyName();
			};
			btnFirewall.Click += delegate
			{
				Firewall.CleanupLegacy();
				FirewallRepairResult repair = Firewall.Repair("Main", FirewallPorts());
				AppendLog(repair.Message);
				MessageBox.Show(this, repair.Message, "NetGate 控制端", MessageBoxButtons.OK, (repair.Ok && repair.Verified) ? MessageBoxIcon.Asterisk : MessageBoxIcon.Warning);
			};
			btnCopyAddr.Click += delegate
			{
				CopyConnInfo();
			};
			chkShowPwd.CheckedChanged += delegate
			{
				UpdateConnInfo();
			};
			chkAutoAllow.CheckedChanged += delegate
			{
				cfg.AutoAllow = chkAutoAllow.Checked;
				cfg.Save();
				AppendLog(cfg.AutoAllow ? "已开启新设备自动允许。" : "已关闭自动允许，新设备需要手动点“允许上网”。");
				RefreshAll();
			};
			btnOpenLog.Click += delegate
			{
				try
				{
					Process.Start("notepad.exe", NetGateServer.LogPath);
				}
				catch
				{
				}
			};
			grid.CellDoubleClick += delegate(object s, DataGridViewCellEventArgs e)
			{
				if (e.RowIndex >= 0)
				{
					SpeedDialog();
				}
			};
			timer = new System.Windows.Forms.Timer
			{
				Interval = 1000
			};
			timer.Tick += delegate
			{
				if (!closing)
				{
					RefreshAll();
				}
				if (Program.SelfTest && Environment.TickCount - testStart > 3000 && !Program.SelfTestDone)
				{
					Program.SelfTestDone = true;
					Program.Dbg("SELFTEST-OK");
					Close();
				}
			};
			testStart = Environment.TickCount;
			timer.Start();
		}

		private static Button BarButton(FlowLayoutPanel bar, string text, int width, bool primary)
		{
			Button button = new Button();
			button.Text = text;
			button.Width = width;
			button.Height = 34;
			button.FlatStyle = FlatStyle.Flat;
			button.Cursor = Cursors.Hand;
			button.Margin = new Padding(0, 8, 8, 8);
			button.Font = new Font("Microsoft YaHei UI", 9f, primary ? FontStyle.Bold : FontStyle.Regular);
			Button button2 = button;
			button2.FlatAppearance.BorderSize = ((!primary) ? 1 : 0);
			button2.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
			button2.BackColor = (primary ? Color.FromArgb(37, 99, 235) : Color.White);
			button2.ForeColor = (primary ? Color.White : Color.FromArgb(30, 41, 59));
			bar.Controls.Add(button2);
			return button2;
		}

		private void AppendLog(string s)
		{
			try
			{
				if (logBox.TextLength > 60000)
				{
					logBox.Clear();
				}
				logBox.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + s + "\r\n");
				logBox.SelectionStart = logBox.TextLength;
				logBox.ScrollToCaret();
			}
			catch
			{
			}
		}

		private void StartEngine()
		{
			try
			{
				NetGateServer.LogPath = Path.Combine(Program.DataDir, "engine.log");
				EngineOptions engineOptions = new EngineOptions();
				engineOptions.ListenPort = cfg.Port;
				EngineOptions o = engineOptions;
				server = NetGateServer.Create(o);
				lock (server.StateLock)
				{
					server.PasswordHash = cfg.Password;
					server.GatewayName = cfg.GatewayName;
				}
				foreach (KeyValuePair<string, long[]> limit in cfg.Limits)
				{
					server.SetLimit(limit.Key, limit.Value[0], limit.Value[1]);
				}
				foreach (KeyValuePair<string, bool> item in cfg.Allowed)
				{
					server.SetAllowed(item.Key, item.Value);
				}
				foreach (KeyValuePair<string, bool> muted in cfg.Muted)
				{
					if (muted.Value)
					{
						server.SetChatMuted(muted.Key, true);
					}
				}
				server.Start();
				AppendLog("代理已启动，监听端口 " + cfg.Port);
				Firewall.CleanupLegacy();
				FirewallRepairResult repair = Firewall.Repair("Main", FirewallPorts());
				AppendLog(repair.Message);
				if ((!repair.Ok || !repair.Verified) && tray != null)
				{
					tray.ShowBalloonTip(3000, "NetGate 控制端", "防火墙规则未完全生效，详见运行日志或 data\\firewall.log。", ToolTipIcon.Warning);
				}
				FileTransferService.EnsureStarted();
				AppendLog("文件传输已启动，端口 " + 8896);
			}
			catch (Exception ex)
			{
				AppendLog("启动失败：" + ex.Message);
				lblStatus.Text = "启动失败";
				lblStatus.ForeColor = Color.FromArgb(248, 113, 113);
				MessageBox.Show("端口 " + cfg.Port + " 启动失败：" + ex.Message + "\r\n可能被其它程序占用。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
		}

		private void RestoreWindow()
		{
			Show();
			if (base.WindowState == FormWindowState.Minimized)
			{
				base.WindowState = FormWindowState.Normal;
			}
			base.ShowInTaskbar = true;
			Activate();
			BringToFront();
		}

		private void ExitApp()
		{
			allowExit = true;
			Close();
		}

		private int[] FirewallPorts()
		{
			List<int> list = new List<int>();
			list.Add(cfg.Port);
			for (int i = 8895; i <= 8905; i++)
			{
				list.Add(i);
			}
			return list.ToArray();
		}

		private void Shutdown()
		{
			try
			{
				if (server != null)
				{
					server.Stop();
				}
			}
			catch
			{
			}
			try
			{
				FileTransferService.StopAll();
			}
			catch
			{
			}
			try
			{
				Firewall.Remove();
			}
			catch
			{
			}
			try
			{
				cfg.Save();
			}
			catch
			{
			}
		}

		private void EnsurePassword(bool firstRun)
		{
			if (string.IsNullOrEmpty(cfg.Password))
			{
				string text = Util.NewPassword(6);
				cfg.Password = NetGateServer.HashPassword(text);
				cfg.PasswordPlain = text;
				cfg.Save();
				lock (server.StateLock)
				{
					server.PasswordHash = cfg.Password;
				}
				AppendLog("已自动生成授权密码：" + text);
				if (tray != null)
				{
					tray.ShowBalloonTip(3000, "NetGate 已就绪", "已自动生成密码，点“复制连接信息”发给要上网的电脑。", ToolTipIcon.Info);
				}
			}
			UpdateConnInfo();
		}

		private void UpdateConnInfo()
		{
			lblAddr.Text = Util.LanIPv4() + ":" + cfg.Port;
			bool flag = !string.IsNullOrEmpty(cfg.PasswordPlain);
			if (flag)
			{
				txtPwd.Text = cfg.PasswordPlain;
				txtPwd.Font = new Font("Consolas", 16f, FontStyle.Bold);
				txtPwd.UseSystemPasswordChar = !chkShowPwd.Checked;
			}
			else
			{
				txtPwd.Text = "已设置（点“换密码”重设）";
				txtPwd.Font = new Font("Microsoft YaHei UI", 9f);
				txtPwd.UseSystemPasswordChar = false;
			}
			chkShowPwd.Enabled = flag;
		}

		private void CopyConnInfo()
		{
			string text = Util.LanIPv4() + ":" + cfg.Port;
			string text2 = (string.IsNullOrEmpty(cfg.PasswordPlain) ? "（请点“换密码”重设）" : cfg.PasswordPlain);
			try
			{
				Clipboard.SetText("NetGate 控制端\r\n地址：" + text + "\r\n密码：" + text2);
				AppendLog("连接信息已复制到剪贴板。");
			}
			catch
			{
			}
		}

		// 改本机名字：会同步到文件传输/聊天列表，以及别的电脑控制端里的「自定义名称」
		private void ChangeMyName()
		{
			string text = NameDialog.Show(this, FileTransferService.Current.LocalName);
			if (!string.IsNullOrEmpty(text))
			{
				FileTransferService.Current.SetLocalName(text);
				AppendLog("本机名称已改为：" + FileTransferService.Current.LocalName);
			}
		}

		private void ChangePassword()
		{
			string text = PasswordDialog.Show(this, cfg.PasswordPlain, false);
			if (!string.IsNullOrEmpty(text))
			{
				cfg.Password = NetGateServer.HashPassword(text);
				cfg.PasswordPlain = text;
				cfg.Save();
				lock (server.StateLock)
				{
					server.PasswordHash = cfg.Password;
				}
				UpdateConnInfo();
				AppendLog("授权密码已更新（已联网的设备需要重新输入）。");
			}
		}

		private void RefreshAll()
		{
			if (server == null)
			{
				return;
			}
			try
			{
				string text = Util.LanIPv4();
				lblAddr.Text = text + ":" + cfg.Port;
				string json = server.StatsJson();
				long num = Util.AsLong(Util.JsonField(json, "online"));
				lblStatus.Text = "运行中 · 在线 " + num + " 台";
				lblStatus.ForeColor = Color.FromArgb(74, 222, 128);
				lblInfo.Text = "累计下载 " + Util.FmtBytes(Util.AsLong(Util.JsonField(json, "down"))) + "    设备总数 " + Util.AsLong(Util.JsonField(json, "devices")) + " 台";
				string json2 = server.DevicesJson();
				List<DeviceView> list = new List<DeviceView>();
				foreach (string item in Util.JsonObjects(json2))
				{
					DeviceView deviceView = new DeviceView();
					deviceView.Mac = Util.JsonField(item, "mac") ?? "";
					deviceView.Ip = Util.JsonField(item, "ip") ?? "";
					deviceView.Name = Util.JsonField(item, "name") ?? "";
					deviceView.Nick = Util.JsonField(item, "nick") ?? "";
					deviceView.User = Util.JsonField(item, "user") ?? "";
					deviceView.Online = Util.AsBool(Util.JsonField(item, "online"));
					deviceView.Allowed = Util.AsBool(Util.JsonField(item, "allowed"));
					deviceView.Pending = Util.AsBool(Util.JsonField(item, "pending"));
					deviceView.Paused = Util.AsBool(Util.JsonField(item, "paused"));
					deviceView.ChatMuted = Util.AsBool(Util.JsonField(item, "chatmuted"));
					deviceView.Up = Util.AsLong(Util.JsonField(item, "up"));
					deviceView.Down = Util.AsLong(Util.JsonField(item, "down"));
					deviceView.CurUp = Util.AsLong(Util.JsonField(item, "curUp"));
					deviceView.CurDown = Util.AsLong(Util.JsonField(item, "curDown"));
					deviceView.LimitUp = Util.AsLong(Util.JsonField(item, "limitUp"));
					deviceView.LimitDown = Util.AsLong(Util.JsonField(item, "limitDown"));
					DateTime result;
					if (DateTime.TryParse(Util.JsonField(item, "last"), out result))
					{
						deviceView.Last = result;
					}
					string name = cfg.GetName(deviceView.Mac);
					if (!string.IsNullOrEmpty(name))
					{
						deviceView.Nick = name;
					}
					list.Add(deviceView);
				}
				// 控制端自己的群聊窗口忽略被禁言设备的消息：按 IP 过滤，客户端不用改
				FileTransferService.SetMutedIps(server.MutedIps());
				if (cfg.AutoAllow)
				{
					bool flag = false;
					foreach (DeviceView item2 in list)
					{
						if (item2.Pending)
						{
							server.SetAllowed(item2.Mac, true);
							cfg.Allowed[item2.Mac] = true;
							item2.Pending = false;
							item2.Allowed = true;
							flag = true;
							AppendLog("已自动允许新设备：" + (string.IsNullOrEmpty(item2.Name) ? item2.Mac : item2.Name) + "（" + item2.Ip + "）");
						}
					}
					if (flag)
					{
						cfg.Save();
					}
				}
				list.Sort(delegate(DeviceView a, DeviceView b)
				{
					if (a.Pending != b.Pending)
					{
						if (!a.Pending)
						{
							return 1;
						}
						return -1;
					}
					return (a.Online != b.Online) ? ((!a.Online) ? 1 : (-1)) : string.Compare((a.Nick ?? "") + " " + a.Name, (b.Nick ?? "") + " " + b.Name, StringComparison.Ordinal);
				});
				string text2 = SelectedMac();
				bool flag2 = list.Count != rows.Count;
				if (!flag2)
				{
					for (int i = 0; i < list.Count; i++)
					{
						DeviceView deviceView2 = list[i];
						DeviceView deviceView3 = rows[i];
						if (deviceView2.Mac != deviceView3.Mac || deviceView2.Online != deviceView3.Online || deviceView2.Allowed != deviceView3.Allowed || deviceView2.Pending != deviceView3.Pending || deviceView2.Paused != deviceView3.Paused || deviceView2.ChatMuted != deviceView3.ChatMuted || deviceView2.LimitDown != deviceView3.LimitDown || deviceView2.LimitUp != deviceView3.LimitUp || deviceView2.Name != deviceView3.Name || deviceView2.Nick != deviceView3.Nick)
						{
							flag2 = true;
							break;
						}
					}
				}
				if (flag2)
				{
					grid.Rows.Clear();
					foreach (DeviceView item3 in list)
					{
						string text3 = (item3.Pending ? "等待允许" : ((!item3.Allowed) ? "未允许" : ((!item3.Online) ? "离线" : (item3.Paused ? "已暂停" : (item3.ChatMuted ? "● 在线 · 已禁言" : "● 在线")))));
						int index = grid.Rows.Add(text3, string.IsNullOrEmpty(item3.Nick) ? "-" : item3.Nick, string.IsNullOrEmpty(item3.Name) ? ("设备 " + item3.Mac.Substring(0, 4)) : item3.Name, item3.Ip, Util.FmtLimit(item3.LimitDown, item3.LimitUp), item3.Online ? (Util.FmtRate(item3.CurDown) + " ↓ / " + Util.FmtRate(item3.CurUp) + " ↑") : "-", Util.FmtBytes(item3.Down) + " ↓ / " + Util.FmtBytes(item3.Up) + " ↑", item3.Online ? DateTime.Now.ToString("HH:mm:ss") : item3.Last.ToString("MM-dd HH:mm"));
						DataGridViewRow dataGridViewRow = grid.Rows[index];
						dataGridViewRow.Tag = item3.Mac;
						if (item3.Pending)
						{
							dataGridViewRow.DefaultCellStyle.BackColor = Color.FromArgb(254, 249, 195);
							dataGridViewRow.DefaultCellStyle.ForeColor = Color.FromArgb(133, 77, 14);
						}
						else if (!item3.Allowed)
						{
							dataGridViewRow.DefaultCellStyle.ForeColor = Color.FromArgb(148, 163, 184);
						}
						else if (item3.Paused)
						{
							dataGridViewRow.DefaultCellStyle.BackColor = Color.FromArgb(254, 242, 242);
						}
						else if (item3.Online)
						{
							dataGridViewRow.DefaultCellStyle.ForeColor = Color.FromArgb(22, 101, 52);
						}
					}
					if (text2 != null)
					{
						foreach (DataGridViewRow item4 in (IEnumerable)grid.Rows)
						{
							if (object.Equals(item4.Tag, text2))
							{
								item4.Selected = true;
								break;
							}
						}
					}
				}
				else
				{
					for (int j = 0; j < list.Count; j++)
					{
						DeviceView deviceView4 = list[j];
						if (j < grid.Rows.Count)
						{
							grid.Rows[j].Cells["rate"].Value = (deviceView4.Online ? (Util.FmtRate(deviceView4.CurDown) + " ↓ / " + Util.FmtRate(deviceView4.CurUp) + " ↑") : "-");
							grid.Rows[j].Cells["total"].Value = Util.FmtBytes(deviceView4.Down) + " ↓ / " + Util.FmtBytes(deviceView4.Up) + " ↑";
						}
					}
				}
				rows = list;
				UpdateActionButtons();
				foreach (DeviceView item5 in list)
				{
					if (item5.Pending && item5.Online && !pendingShown.Contains(item5.Mac))
					{
						pendingShown.Add(item5.Mac);
						AppendLog("新设备请求上网：" + (string.IsNullOrEmpty(item5.Name) ? item5.Mac : item5.Name) + "（" + item5.Ip + "）— 请在上方点“允许上网”");
					}
					if (!item5.Pending && !item5.Online)
					{
						pendingShown.Remove(item5.Mac);
					}
				}
			}
			catch (Exception ex)
			{
				Program.Dbg("refresh: " + ex.Message);
			}
		}

		private string SelectedMac()
		{
			if (grid.CurrentRow == null)
			{
				return null;
			}
			return grid.CurrentRow.Tag as string;
		}

		private DeviceView SelectedDevice()
		{
			string text = SelectedMac();
			if (text == null)
			{
				return null;
			}
			foreach (DeviceView row in rows)
			{
				if (row.Mac == text)
				{
					return row;
				}
			}
			return null;
		}

		private void AllowSelected(bool allow)
		{
			DeviceView deviceView = SelectedDevice();
			if (deviceView == null)
			{
				MessageBox.Show("请先在列表里点选一台设备。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			server.SetAllowed(deviceView.Mac, allow);
			if (allow)
			{
				cfg.Allowed[deviceView.Mac] = true;
				cfg.Save();
			}
			else
			{
				server.Kick(deviceView.Mac);
				cfg.Allowed.Remove(deviceView.Mac);
				cfg.Save();
			}
			AppendLog((allow ? "已允许 " : "已断开/禁止 ") + DisplayName(deviceView));
			RefreshAll();
		}

		private void PauseSelected()
		{
			DeviceView deviceView = SelectedDevice();
			if (deviceView == null)
			{
				MessageBox.Show("请先在列表里点选一台设备。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			bool flag = !deviceView.Paused;
			server.SetPaused(deviceView.Mac, flag);
			AppendLog((flag ? "已暂停 " : "已恢复 ") + DisplayName(deviceView));
			RefreshAll();
		}

		private string DisplayName(DeviceView d)
		{
			if (!string.IsNullOrEmpty(d.Name))
			{
				return d.Name + " (" + d.Ip + ")";
			}
			return d.Mac;
		}

		private void SpeedDialog()
		{
			DeviceView deviceView = SelectedDevice();
			if (deviceView == null)
			{
				MessageBox.Show("请先在列表里点选一台设备。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			using (SpeedForm speedForm = new SpeedForm(deviceView.Name, deviceView.LimitDown, deviceView.LimitUp))
			{
				if (speedForm.ShowDialog(this) == DialogResult.OK)
				{
					cfg.Limits[deviceView.Mac] = new long[2] { speedForm.UpKb, speedForm.DownKb };
					cfg.Save();
					server.SetLimit(deviceView.Mac, speedForm.UpKb, speedForm.DownKb);
					AppendLog("已设置限速 " + DisplayName(deviceView) + " → " + Util.FmtLimit(speedForm.DownKb, speedForm.UpKb));
					RefreshAll();
				}
			}
		}

		private void BuildUiModern()
		{
			SuspendLayout();
			UiKit.Apply(this);
			DoubleBuffered = true;
			Text = "NetGate 控制端";
			base.Size = new Size(1120, 760);
			MinimumSize = new Size(1000, 660);

			TableLayoutPanel root = new TableLayoutPanel();
			root.Dock = DockStyle.Fill;
			root.ColumnCount = 1;
			root.RowCount = 3;
			root.BackColor = UiKit.Bg;
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64f));
			root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
			base.Controls.Add(root);

			Panel header = new Panel();
			header.Dock = DockStyle.Fill;
			header.BackColor = UiKit.Header;
			root.Controls.Add(header, 0, 0);
			header.Controls.Add(new Label
			{
				Text = "NetGate 控制端",
				ForeColor = Color.White,
				Font = UiKit.Title,
				AutoSize = true,
				Location = new Point(20, 18)
			});
			FlowLayoutPanel headerRight = new FlowLayoutPanel();
			headerRight.Dock = DockStyle.Right;
			headerRight.Width = 420;
			headerRight.FlowDirection = FlowDirection.RightToLeft;
			headerRight.WrapContents = false;
			headerRight.BackColor = UiKit.Header;
			headerRight.Padding = new Padding(0, 22, 20, 0);
			header.Controls.Add(headerRight);
			lblStatus = new Label();
			lblStatus.Text = "正在启动…";
			lblStatus.ForeColor = UiKit.HeaderText;
			lblStatus.Font = UiKit.Body;
			lblStatus.AutoSize = true;
			lblStatus.Margin = new Padding(0);
			headerRight.Controls.Add(lblStatus);

			Panel body = new Panel();
			body.Dock = DockStyle.Fill;
			body.BackColor = UiKit.Bg;
			body.Padding = new Padding(16, 16, 16, 12);
			root.Controls.Add(body, 0, 1);

			TableLayoutPanel stack = new TableLayoutPanel();
			stack.Dock = DockStyle.Fill;
			stack.ColumnCount = 1;
			stack.RowCount = 2;
			stack.BackColor = UiKit.Bg;
			stack.RowStyles.Add(new RowStyle(SizeType.Absolute, 164f));
			stack.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			body.Controls.Add(stack);

			Panel conn = UiKit.CardPanel();
			conn.Dock = DockStyle.Fill;
			conn.Margin = new Padding(0, 0, 0, 12);
			conn.Padding = new Padding(20, 14, 20, 12);
			stack.Controls.Add(conn, 0, 0);

			TableLayoutPanel connLayout = new TableLayoutPanel();
			connLayout.Dock = DockStyle.Fill;
			connLayout.ColumnCount = 2;
			connLayout.RowCount = 3;
			connLayout.BackColor = UiKit.Card;
			connLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52f));
			connLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48f));
			connLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 24f));
			connLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 54f));
			connLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			conn.Controls.Add(connLayout);

			connLayout.Controls.Add(UiKit.FieldLabel("网关地址"), 0, 0);
			connLayout.Controls.Add(UiKit.FieldLabel("授权密码"), 1, 0);

			lblAddr = new Label();
			lblAddr.Text = "正在获取本机地址…";
			lblAddr.ForeColor = UiKit.Primary;
			lblAddr.Font = UiKit.Value;
			lblAddr.AutoSize = false;
			lblAddr.Dock = DockStyle.Fill;
			lblAddr.TextAlign = ContentAlignment.MiddleLeft;
			lblAddr.Margin = new Padding(0);
			connLayout.Controls.Add(lblAddr, 0, 1);

			FlowLayoutPanel pwdRow = new FlowLayoutPanel();
			pwdRow.Dock = DockStyle.Fill;
			pwdRow.FlowDirection = FlowDirection.LeftToRight;
			pwdRow.WrapContents = false;
			pwdRow.BackColor = UiKit.Card;
			pwdRow.Margin = new Padding(0);
			pwdRow.Padding = new Padding(0, 6, 0, 0);
			connLayout.Controls.Add(pwdRow, 1, 1);

			txtPwd = new TextBox();
			txtPwd.Size = new Size(220, 34);
			txtPwd.Font = UiKit.Password;
			txtPwd.ReadOnly = true;
			txtPwd.BorderStyle = BorderStyle.FixedSingle;
			txtPwd.TextAlign = HorizontalAlignment.Left;
			txtPwd.BackColor = Color.White;
			txtPwd.ForeColor = UiKit.TextColor;
			txtPwd.Margin = new Padding(0, 0, 12, 0);
			pwdRow.Controls.Add(txtPwd);

			chkShowPwd = new CheckBox();
			chkShowPwd.Text = "显示";
			chkShowPwd.AutoSize = true;
			chkShowPwd.ForeColor = UiKit.Muted;
			chkShowPwd.Margin = new Padding(0, 8, 0, 0);
			pwdRow.Controls.Add(chkShowPwd);

			FlowLayoutPanel connActions = new FlowLayoutPanel();
			connActions.Dock = DockStyle.Fill;
			connActions.FlowDirection = FlowDirection.LeftToRight;
			connActions.WrapContents = false;
			connActions.BackColor = UiKit.Card;
			connActions.Margin = new Padding(0);
			connLayout.SetColumnSpan(connActions, 2);
			connLayout.Controls.Add(connActions, 0, 2);

			btnCopyAddr = UiKit.PrimaryButton("复制连接信息");
			btnCopyAddr.Width = 132;
			connActions.Controls.Add(btnCopyAddr);
			btnPwd = UiKit.SecondaryButton("修改密码");
			btnPwd.Width = 96;
			connActions.Controls.Add(btnPwd);

			Panel listCard = UiKit.CardPanel();
			listCard.Dock = DockStyle.Fill;
			listCard.Margin = new Padding(0, 12, 0, 0);
			listCard.Padding = new Padding(16, 10, 16, 12);
			stack.Controls.Add(listCard, 0, 1);

			TableLayoutPanel listLayout = new TableLayoutPanel();
			listLayout.Dock = DockStyle.Fill;
			listLayout.ColumnCount = 1;
			listLayout.RowCount = 3;
			listLayout.BackColor = UiKit.Card;
			listLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
			listLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46f));
			listLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			listCard.Controls.Add(listLayout);

			Panel listTitle = new Panel();
			listTitle.Dock = DockStyle.Fill;
			listTitle.BackColor = UiKit.Card;
			listLayout.Controls.Add(listTitle, 0, 0);
			listTitle.Controls.Add(new Label
			{
				Text = "设备列表",
				Font = UiKit.SubTitle,
				ForeColor = UiKit.TextColor,
				AutoSize = true,
				Location = new Point(0, 2)
			});
			FlowLayoutPanel titleRight = new FlowLayoutPanel();
			titleRight.Dock = DockStyle.Right;
			titleRight.Width = 190;
			titleRight.FlowDirection = FlowDirection.RightToLeft;
			titleRight.WrapContents = false;
			titleRight.BackColor = UiKit.Card;
			titleRight.Padding = new Padding(0, 4, 0, 0);
			listTitle.Controls.Add(titleRight);
			chkAutoAllow = new CheckBox();
			chkAutoAllow.Text = "新设备自动允许";
			chkAutoAllow.AutoSize = true;
			chkAutoAllow.Checked = cfg.AutoAllow;
			chkAutoAllow.ForeColor = UiKit.TextColor;
			chkAutoAllow.Margin = new Padding(0);
			titleRight.Controls.Add(chkAutoAllow);

			FlowLayoutPanel toolbar = new FlowLayoutPanel();
			toolbar.Dock = DockStyle.Fill;
			toolbar.FlowDirection = FlowDirection.LeftToRight;
			toolbar.WrapContents = false;
			toolbar.AutoScroll = true;
			toolbar.BackColor = UiKit.Card;
			toolbar.Padding = new Padding(0, 6, 0, 0);
			listLayout.Controls.Add(toolbar, 0, 1);

			btnAllow = UiKit.ToolButton("允许上网", true);
			btnDeny = UiKit.ToolButton("断开 / 禁止", false);
			btnPause = UiKit.ToolButton("暂停 / 恢复", false);
			btnSpeed = UiKit.ToolButton("限速设置…", false);
			btnRefresh = UiKit.ToolButton("刷新", false);
			btnFiles = UiKit.ToolButton("文件传输…", false);
			btnChat = UiKit.ToolButton("群聊…", false);
			btnName = UiKit.ToolButton("我的名称…", false);
			btnFirewall = UiKit.ToolButton("修复防火墙", false);
			Button btnLogTab = UiKit.ToolButton("日志", false);
			btnAllow.Width = 96;
			btnDeny.Width = 104;
			btnPause.Width = 104;
			btnSpeed.Width = 104;
			btnRefresh.Width = 70;
			btnFiles.Width = 104;
			btnChat.Width = 82;
			btnName.Width = 104;
			btnFirewall.Width = 96;
			btnLogTab.Width = 70;
			toolbar.Controls.Add(btnAllow);
			toolbar.Controls.Add(btnDeny);
			toolbar.Controls.Add(btnPause);
			toolbar.Controls.Add(btnSpeed);
			toolbar.Controls.Add(btnRefresh);
			toolbar.Controls.Add(btnFiles);
			toolbar.Controls.Add(btnChat);
			toolbar.Controls.Add(btnName);
			toolbar.Controls.Add(btnFirewall);
			toolbar.Controls.Add(btnLogTab);

			TabControl tabs = new TabControl();
			tabs.Dock = DockStyle.Fill;
			tabs.Font = UiKit.Body;
			tabs.Padding = new Point(16, 6);
			listLayout.Controls.Add(tabs, 0, 2);

			TabPage devicePage = new TabPage();
			devicePage.Text = "设备";
			devicePage.BackColor = UiKit.Card;
			devicePage.Padding = new Padding(0);
			tabs.TabPages.Add(devicePage);

			TabPage logPage = new TabPage();
			logPage.Text = "运行日志";
			logPage.BackColor = UiKit.Card;
			logPage.Padding = new Padding(0);
			tabs.TabPages.Add(logPage);

			grid = new DataGridView();
			grid.Dock = DockStyle.Fill;
			UiKit.StyleGrid(grid);
			string[][] columns = new string[8][]
			{
				new string[2] { "status", "状态" },
				new string[2] { "nick", "自定义名称" },
				new string[2] { "name", "计算机名" },
				new string[2] { "ip", "IP 地址" },
				new string[2] { "limit", "限速" },
				new string[2] { "rate", "当前速度" },
				new string[2] { "total", "累计流量" },
				new string[2] { "last", "最近在线" }
			};
			foreach (string[] columnInfo in columns)
			{
				DataGridViewTextBoxColumn column = new DataGridViewTextBoxColumn();
				column.Name = columnInfo[0];
				column.HeaderText = columnInfo[1];
				column.SortMode = DataGridViewColumnSortMode.NotSortable;
				if (columnInfo[0] == "nick")
				{
					column.FillWeight = 150f;
				}
				else if (columnInfo[0] == "name")
				{
					column.FillWeight = 130f;
				}
				else if (columnInfo[0] == "status")
				{
					column.FillWeight = 80f;
				}
				else if (columnInfo[0] == "ip")
				{
					column.FillWeight = 110f;
				}
				else if (columnInfo[0] == "rate")
				{
					column.FillWeight = 120f;
				}
				else if (columnInfo[0] == "total")
				{
					column.FillWeight = 130f;
				}
				grid.Columns.Add(column);
			}
			devicePage.Controls.Add(grid);

			Panel logPageLayout = new Panel();
			logPageLayout.Dock = DockStyle.Fill;
			logPageLayout.BackColor = UiKit.Card;
			logPageLayout.Padding = new Padding(0, 8, 0, 0);
			logPage.Controls.Add(logPageLayout);

			FlowLayoutPanel logActions = new FlowLayoutPanel();
			logActions.Dock = DockStyle.Top;
			logActions.Height = 38;
			logActions.FlowDirection = FlowDirection.LeftToRight;
			logActions.WrapContents = false;
			logActions.BackColor = UiKit.Card;
			logPageLayout.Controls.Add(logActions);
			btnOpenLog = UiKit.SecondaryButton("用记事本打开");
			btnOpenLog.Width = 112;
			logActions.Controls.Add(btnOpenLog);
			Button btnClearLog = UiKit.SecondaryButton("清空");
			btnClearLog.Width = 70;
			logActions.Controls.Add(btnClearLog);

			logBox = new TextBox();
			logBox.Dock = DockStyle.Fill;
			logBox.Multiline = true;
			logBox.ReadOnly = true;
			logBox.ScrollBars = ScrollBars.Vertical;
			logBox.BackColor = Color.FromArgb(250, 251, 253);
			logBox.BorderStyle = BorderStyle.FixedSingle;
			logBox.Font = UiKit.Mono;
			logPageLayout.Controls.Add(logBox);

			lblInfo = new Label();
			Panel status = UiKit.StatusBar(lblInfo);
			root.Controls.Add(status, 0, 2);

			btnPwd.Click += delegate
			{
				ChangePassword();
			};
			btnAllow.Click += delegate
			{
				AllowSelected(true);
			};
			btnDeny.Click += delegate
			{
				AllowSelected(false);
			};
			btnPause.Click += delegate
			{
				PauseSelected();
			};
			btnSpeed.Click += delegate
			{
				SpeedDialog();
			};
			btnRefresh.Click += delegate
			{
				RefreshAll();
			};
			btnFiles.Click += delegate
			{
				HubForm.ShowShared(this, server, cfg, 1);
			};
			btnChat.Click += delegate
			{
				HubForm.ShowShared(this, server, cfg, 0);
			};
			btnName.Click += delegate
			{
				ChangeMyName();
			};
			btnFirewall.Click += delegate
			{
				Firewall.CleanupLegacy();
				FirewallRepairResult repair = Firewall.Repair("Main", FirewallPorts());
				AppendLog(repair.Message);
				MessageBox.Show(this, repair.Message, "NetGate 控制端", MessageBoxButtons.OK, (repair.Ok && repair.Verified) ? MessageBoxIcon.Asterisk : MessageBoxIcon.Warning);
			};
			btnCopyAddr.Click += delegate
			{
				CopyConnInfo();
			};
			chkShowPwd.CheckedChanged += delegate
			{
				UpdateConnInfo();
			};
			chkAutoAllow.CheckedChanged += delegate
			{
				cfg.AutoAllow = chkAutoAllow.Checked;
				cfg.Save();
				AppendLog(cfg.AutoAllow ? "已开启新设备自动允许。" : "已关闭自动允许，新设备需要手动点“允许上网”。");
				RefreshAll();
			};
			btnOpenLog.Click += delegate
			{
				try
				{
					Process.Start("notepad.exe", NetGateServer.LogPath);
				}
				catch
				{
				}
			};
			btnClearLog.Click += delegate
			{
				logBox.Clear();
			};
			btnLogTab.Click += delegate
			{
				tabs.SelectedTab = logPage;
			};
			grid.CellDoubleClick += delegate(object s, DataGridViewCellEventArgs e)
			{
				if (e.RowIndex >= 0)
				{
					SpeedDialog();
				}
			};
			grid.SelectionChanged += delegate
			{
				UpdateActionButtons();
			};
			timer = new System.Windows.Forms.Timer();
			timer.Interval = 1000;
			timer.Tick += delegate
			{
				if (!closing)
				{
					RefreshAll();
				}
				if (Program.SelfTest && Environment.TickCount - testStart > 3000 && !Program.SelfTestDone)
				{
					Program.SelfTestDone = true;
					Program.Dbg("SELFTEST-OK");
					Close();
				}
			};
			testStart = Environment.TickCount;
			timer.Start();
			UpdateActionButtons();
			ResumeLayout();
		}

		private void UpdateActionButtons()
		{
			bool flag = grid != null && grid.CurrentRow != null && grid.CurrentRow.Tag != null;
			if (btnAllow != null)
			{
				btnAllow.Enabled = flag;
			}
			if (btnDeny != null)
			{
				btnDeny.Enabled = flag;
			}
			if (btnPause != null)
			{
				btnPause.Enabled = flag;
			}
			if (btnSpeed != null)
			{
				btnSpeed.Enabled = flag;
			}
		}
	}
	internal class PasswordDialog : Form
	{
		private string value;

		private PasswordDialog(string initial, bool isFirst)
		{
			Text = (isFirst ? "设置授权密码" : "修改授权密码");
			base.Size = new Size(480, 340);
			base.StartPosition = FormStartPosition.CenterParent;
			base.FormBorderStyle = FormBorderStyle.FixedDialog;
			base.MaximizeBox = false;
			base.MinimizeBox = false;
			UiKit.Apply(this);
			base.BackColor = Color.White;
			base.Padding = new Padding(24, 20, 24, 20);

			TableLayoutPanel layout = new TableLayoutPanel();
			layout.Dock = DockStyle.Fill;
			layout.ColumnCount = 1;
			layout.RowCount = 5;
			layout.BackColor = Color.White;
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34f));
			layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			base.Controls.Add(layout);

			Label intro = new Label();
			intro.Text = (isFirst ? "所有需要上网的电脑共用这个密码。" : "修改后，已联网的设备需要重新输入。");
			intro.ForeColor = UiKit.Muted;
			intro.Font = UiKit.Body;
			intro.AutoSize = false;
			intro.Dock = DockStyle.Fill;
			intro.TextAlign = ContentAlignment.MiddleLeft;
			layout.Controls.Add(intro, 0, 0);

			TableLayoutPanel firstRow = new TableLayoutPanel();
			firstRow.Dock = DockStyle.Fill;
			firstRow.ColumnCount = 1;
			firstRow.RowCount = 2;
			firstRow.BackColor = Color.White;
			firstRow.RowStyles.Add(new RowStyle(SizeType.Absolute, 24f));
			firstRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			layout.Controls.Add(firstRow, 0, 1);
			firstRow.Controls.Add(UiKit.FieldLabel("授权密码（4 位以上）"), 0, 0);
			TextBox tb = new TextBox();
			tb.Dock = DockStyle.Fill;
			tb.Font = new Font("Microsoft YaHei UI", 10f);
			tb.BorderStyle = BorderStyle.FixedSingle;
			tb.Text = initial;
			tb.UseSystemPasswordChar = true;
			tb.Margin = new Padding(0);
			firstRow.Controls.Add(tb, 0, 1);

			TableLayoutPanel secondRow = new TableLayoutPanel();
			secondRow.Dock = DockStyle.Fill;
			secondRow.ColumnCount = 1;
			secondRow.RowCount = 2;
			secondRow.BackColor = Color.White;
			secondRow.RowStyles.Add(new RowStyle(SizeType.Absolute, 24f));
			secondRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			layout.Controls.Add(secondRow, 0, 2);
			secondRow.Controls.Add(UiKit.FieldLabel("再次输入"), 0, 0);
			TextBox tb2 = new TextBox();
			tb2.Dock = DockStyle.Fill;
			tb2.Font = new Font("Microsoft YaHei UI", 10f);
			tb2.BorderStyle = BorderStyle.FixedSingle;
			tb2.Text = initial;
			tb2.UseSystemPasswordChar = true;
			tb2.Margin = new Padding(0);
			secondRow.Controls.Add(tb2, 0, 1);

			CheckBox chk = new CheckBox();
			chk.Text = "显示密码";
			chk.AutoSize = true;
			chk.ForeColor = UiKit.Muted;
			chk.Margin = new Padding(0, 8, 0, 0);
			chk.CheckedChanged += delegate
			{
				tb.UseSystemPasswordChar = !chk.Checked;
				tb2.UseSystemPasswordChar = !chk.Checked;
			};
			layout.Controls.Add(chk, 0, 3);

			FlowLayoutPanel buttons = new FlowLayoutPanel();
			buttons.Dock = DockStyle.Fill;
			buttons.FlowDirection = FlowDirection.RightToLeft;
			buttons.WrapContents = false;
			buttons.BackColor = Color.White;
			layout.Controls.Add(buttons, 0, 4);

			Button button = UiKit.PrimaryButton("确定");
			button.Width = 88;
			button.DialogResult = DialogResult.None;
			buttons.Controls.Add(button);
			Button cancelButton = UiKit.SecondaryButton("取消");
			cancelButton.Width = 88;
			cancelButton.DialogResult = DialogResult.Cancel;
			buttons.Controls.Add(cancelButton);
			base.CancelButton = cancelButton;
			base.AcceptButton = button;
			button.Click += delegate
			{
				string text = tb.Text.Trim();
				string text2 = tb2.Text.Trim();
				if (text.Length < 4)
				{
					MessageBox.Show("密码至少 4 位。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
				}
				else if (text != text2)
				{
					MessageBox.Show("两次输入的密码不一致。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
				}
				else
				{
					value = text;
					base.DialogResult = DialogResult.OK;
					Close();
				}
			};
			if (isFirst)
			{
				tb.SelectionStart = tb.TextLength;
			}
		}

		public static string Show(IWin32Window owner, string initial, bool isFirst)
		{
			using (PasswordDialog passwordDialog = new PasswordDialog(initial, isFirst))
			{
				return (passwordDialog.ShowDialog(owner) == DialogResult.OK) ? passwordDialog.value : null;
			}
		}
	}
	internal class SpeedForm : Form
	{
		public long DownKb;

		public long UpKb;

		private NumericUpDown numDown;

		private NumericUpDown numUp;

		public SpeedForm(string name, long down, long up)
		{
			Text = "限速设置 - " + (string.IsNullOrEmpty(name) ? "设备" : name);
			base.Size = new Size(480, 380);
			base.StartPosition = FormStartPosition.CenterParent;
			base.FormBorderStyle = FormBorderStyle.FixedDialog;
			base.MaximizeBox = false;
			base.MinimizeBox = false;
			UiKit.Apply(this);
			base.BackColor = Color.White;
			base.Padding = new Padding(24, 20, 24, 20);

			TableLayoutPanel layout = new TableLayoutPanel();
			layout.Dock = DockStyle.Fill;
			layout.ColumnCount = 1;
			layout.RowCount = 8;
			layout.BackColor = Color.White;
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
			layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			base.Controls.Add(layout);

			layout.Controls.Add(UiKit.FieldLabel("下载限速（KB/s，0 表示不限速）"), 0, 0);
			numDown = new NumericUpDown();
			numDown.Width = 220;
			numDown.Maximum = 2000000m;
			numDown.Minimum = 0m;
			numDown.Increment = 50m;
			numDown.Value = down;
			numDown.Margin = new Padding(0, 4, 0, 0);
			layout.Controls.Add(numDown, 0, 1);

			layout.Controls.Add(UiKit.FieldLabel("上传限速（KB/s，0 表示不限速）"), 0, 2);
			numUp = new NumericUpDown();
			numUp.Width = 220;
			numUp.Maximum = 2000000m;
			numUp.Minimum = 0m;
			numUp.Increment = 50m;
			numUp.Value = up;
			numUp.Margin = new Padding(0, 4, 0, 0);
			layout.Controls.Add(numUp, 0, 3);

			layout.Controls.Add(UiKit.FieldLabel("常用方案"), 0, 4);
			FlowLayoutPanel presets = new FlowLayoutPanel();
			presets.Dock = DockStyle.Fill;
			presets.FlowDirection = FlowDirection.LeftToRight;
			presets.WrapContents = false;
			presets.BackColor = Color.White;
			presets.Margin = new Padding(0);
			layout.Controls.Add(presets, 0, 5);
			string[][] array = new string[5][]
			{
				new string[3] { "1 Mbps", "128", "1024" },
				new string[3] { "2 Mbps", "256", "2048" },
				new string[3] { "5 Mbps", "640", "5120" },
				new string[3] { "10 Mbps", "1280", "10240" },
				new string[3] { "不限速", "0", "0" }
			};
			foreach (string[] array3 in array)
			{
				long down2 = Util.AsLong(array3[1]);
				long up2 = Util.AsLong(array3[2]);
				Button preset = UiKit.SecondaryButton(array3[0]);
				preset.Width = 82;
				preset.Height = 30;
				preset.Click += delegate
				{
					numDown.Value = down2;
					numUp.Value = up2;
				};
				presets.Controls.Add(preset);
			}

			Label note = new Label();
			note.Text = "1000 KB/s = 1 MB/s，约等于 8 Mbps 宽带。";
			note.ForeColor = UiKit.Muted;
			note.Font = UiKit.Body;
			note.AutoSize = false;
			note.Dock = DockStyle.Fill;
			note.TextAlign = ContentAlignment.MiddleLeft;
			layout.Controls.Add(note, 0, 6);

			FlowLayoutPanel buttons = new FlowLayoutPanel();
			buttons.Dock = DockStyle.Fill;
			buttons.FlowDirection = FlowDirection.RightToLeft;
			buttons.WrapContents = false;
			buttons.BackColor = Color.White;
			layout.Controls.Add(buttons, 0, 7);
			Button button2 = UiKit.PrimaryButton("应用");
			button2.Width = 88;
			buttons.Controls.Add(button2);
			Button button3 = UiKit.SecondaryButton("取消");
			button3.Width = 88;
			button3.DialogResult = DialogResult.Cancel;
			buttons.Controls.Add(button3);
			base.CancelButton = button3;
			base.AcceptButton = button2;
			button2.Click += delegate
			{
				DownKb = (long)numDown.Value;
				UpKb = (long)numUp.Value;
				base.DialogResult = DialogResult.OK;
				Close();
			};
		}
	}
	public sealed class FirewallRepairResult
	{
		public bool Ok;

		public bool Ports;

		public bool Program;

		public bool Verified;

		public int BlockRulesRemoved;

		public string Message = "";
	}
	internal static class Firewall
	{
		private static readonly string[] LegacyRules = new string[6] { "NetGate_AllowProxy", "NetGate_AllowLoopback", "NetGate_BlockOut", "NetGate_BlockOutUdp", "NetGate_AllowInTCP", "NetGate_AllowInUDP" };

		public static void CleanupLegacy()
		{
			bool flag = RuleExists("NetGate_BlockOut") || RuleExists("NetGate_BlockOutUdp");
			string[] legacyRules = LegacyRules;
			foreach (string text in legacyRules)
			{
				Run("netsh", "advfirewall firewall delete rule name=" + text);
			}
			if (flag)
			{
				Run("netsh", "advfirewall set privateprofile firewallpolicy allowinbound,allowoutbound");
				Run("netsh", "advfirewall set domainprofile firewallpolicy allowinbound,allowoutbound");
			}
		}

		private static bool RuleExists(string name)
		{
			return Run("netsh", "advfirewall firewall show rule name=" + name);
		}

		public static bool RulesPresent(string tag)
		{
			return RuleExists("NetGate_AllowInTCP_" + tag) && RuleExists("NetGate_AllowInUDP_" + tag) && RuleExists("NetGate_AllowApp_" + tag);
		}

		/// <summary>
		/// 完整的防火墙自愈：清阻止规则 → 重建端口规则 → 重建程序规则 → 校验。
		/// 启动、运行中看门狗和界面“修复防火墙”都走这一套，避免各入口行为不一致。
		/// </summary>
		public static FirewallRepairResult Repair(string tag, params int[] ports)
		{
			FirewallRepairResult result = new FirewallRepairResult();
			try
			{
				result.BlockRulesRemoved = RemoveSelfBlockRules();
				result.Ports = OpenPorts(tag, ports);
				result.Program = OpenProgram(tag);
				bool tcp = RuleExists("NetGate_AllowInTCP_" + tag);
				bool udp = RuleExists("NetGate_AllowInUDP_" + tag);
				bool app = RuleExists("NetGate_AllowApp_" + tag);
				result.Verified = tcp && udp && app;
				result.Ok = result.Ports && result.Program;
				if (result.Ok && result.Verified)
				{
					result.Message = "防火墙规则已修复并校验通过（端口 + 程序放行）" + ((result.BlockRulesRemoved > 0) ? ("，清除阻止规则 " + result.BlockRulesRemoved + " 条") : "");
				}
				else if (result.Ok)
				{
					result.Message = "防火墙规则已添加，但校验未通过（可能被组策略或安全软件延迟/拦截），详见 data\\firewall.log";
				}
				else
				{
					result.Message = "防火墙修复未完全成功：端口=" + (result.Ports ? "ok" : "失败") + "，程序=" + (result.Program ? "ok" : "失败") + "，校验=" + (result.Verified ? "ok" : "失败") + "（可能被组策略或安全软件拦截，详见 data\\firewall.log）";
				}
				Program.LogFirewall("repair " + tag + ": ports=" + (result.Ports ? "ok" : "FAIL") + " program=" + (result.Program ? "ok" : "FAIL") + " verify=" + (result.Verified ? "ok" : "FAIL") + " blockRemoved=" + result.BlockRulesRemoved);
			}
			catch (Exception ex)
			{
				result.Ok = false;
				result.Message = "防火墙修复异常：" + ex.Message + "（详见 data\\firewall.log）";
				Program.LogFirewall("repair " + tag + " ERROR: " + ex.Message);
			}
			return result;
		}

		public static bool OpenPorts(params int[] ports)
		{
			return OpenPorts("Main", ports);
		}

		public static bool OpenPorts(string tag, params int[] ports)
		{
			try
			{
				List<int> list = new List<int>();
				foreach (int num in ports)
				{
					if (num > 0 && num <= 65535 && !list.Contains(num))
					{
						list.Add(num);
					}
				}
				if (list.Count == 0)
				{
					return false;
				}
				string text = "NetGate_AllowInTCP_" + tag;
				string text2 = "NetGate_AllowInUDP_" + tag;
				string text3 = string.Join(",", list.ConvertAll((int p) => p.ToString()).ToArray());
				Run("netsh", "advfirewall firewall delete rule name=" + text);
				Run("netsh", "advfirewall firewall delete rule name=" + text2);
				bool flag = Run("netsh", "advfirewall firewall add rule name=" + text + " dir=in action=allow protocol=TCP localport=" + text3 + " profile=any");
				return flag & Run("netsh", "advfirewall firewall add rule name=" + text2 + " dir=in action=allow protocol=UDP localport=" + text3 + " profile=any");
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// 按程序放行入站。端口规则万一被组策略 / 安全软件改掉，这条还能兜底；
		/// 也方便「扫描不到对方」时判断到底是端口规则没生效还是网络本身不通。
		/// </summary>
		public static bool OpenProgram(string tag)
		{
			try
			{
				string text = "NetGate_AllowApp_" + tag;
				Run("netsh", "advfirewall firewall delete rule name=" + text);
				return Run("netsh", "advfirewall firewall add rule name=" + text + " dir=in action=allow program=\"" + Program.SelfPath + "\" enable=yes profile=any");
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// 删除「本程序自己」的入站阻止规则。
		/// 用户点了 Windows 防火墙弹窗的「取消」时，系统会给程序写 dir=in action=block 规则，
		/// 这类规则的优先级高于端口放行规则，表现就是「本机一切正常，别的电脑却扫不到、连不上」。
		/// 走防火墙 COM 接口按程序路径枚举，与系统语言无关；返回删除的条数（0 表示没被挡）。
		/// </summary>
		public static int RemoveSelfBlockRules()
		{
			int num = 0;
			try
			{
				Type typeFromProgID = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
				if (typeFromProgID == null)
				{
					return 0;
				}
				object obj = Activator.CreateInstance(typeFromProgID);
				object obj2 = typeFromProgID.InvokeMember("Rules", BindingFlags.GetProperty, null, obj, null);
				List<string> list = new List<string>();
				foreach (object item in (IEnumerable)obj2)
				{
					try
					{
						Type type = item.GetType();
						string text = Convert.ToString(type.InvokeMember("ApplicationName", BindingFlags.GetProperty, null, item, null));
						if (string.IsNullOrEmpty(text) || !string.Equals(text, Program.SelfPath, StringComparison.OrdinalIgnoreCase))
						{
							continue;
						}
						if (Convert.ToInt32(type.InvokeMember("Action", BindingFlags.GetProperty, null, item, null)) != 0 || Convert.ToInt32(type.InvokeMember("Direction", BindingFlags.GetProperty, null, item, null)) != 1)
						{
							continue;
						}
						string text2 = Convert.ToString(type.InvokeMember("Name", BindingFlags.GetProperty, null, item, null));
						if (!string.IsNullOrEmpty(text2))
						{
							list.Add(text2);
						}
					}
					catch
					{
					}
				}
				foreach (string item2 in list)
				{
					try
					{
						obj2.GetType().InvokeMember("Remove", BindingFlags.InvokeMethod, null, obj2, new object[1] { item2 });
						num++;
					}
					catch
					{
					}
				}
			}
			catch
			{
			}
			return num;
		}

		public static void Remove()
		{
			string[] array = new string[2] { "Main", "File" };
			foreach (string text in array)
			{
				Run("netsh", "advfirewall firewall delete rule name=NetGate_AllowInTCP_" + text);
				Run("netsh", "advfirewall firewall delete rule name=NetGate_AllowInUDP_" + text);
				Run("netsh", "advfirewall firewall delete rule name=NetGate_AllowApp_" + text);
			}
			string[] legacyRules = LegacyRules;
			foreach (string text2 in legacyRules)
			{
				Run("netsh", "advfirewall firewall delete rule name=" + text2);
			}
		}

		private static bool Run(string file, string args)
		{
			try
			{
				ProcessStartInfo processStartInfo = new ProcessStartInfo(file, args);
				processStartInfo.UseShellExecute = false;
				processStartInfo.CreateNoWindow = true;
				processStartInfo.RedirectStandardOutput = true;
				processStartInfo.RedirectStandardError = true;
				ProcessStartInfo startInfo = processStartInfo;
				using (Process process = Process.Start(startInfo))
				{
					string text2 = process.StandardError.ReadToEnd();
					process.WaitForExit(8000);
					bool flag = process.ExitCode == 0;
					if (!flag && args.IndexOf("add rule", StringComparison.OrdinalIgnoreCase) >= 0)
					{
						Program.LogFirewall("netsh FAIL: " + args + " | " + text2.Trim());
					}
					return flag;
				}
			}
			catch (Exception ex)
			{
				if (args.IndexOf("add rule", StringComparison.OrdinalIgnoreCase) >= 0)
				{
					Program.LogFirewall("netsh ERROR: " + args + " | " + ex.Message);
				}
				return false;
			}
		}
	}
	internal static class NetGateIcon
	{
		private static Icon cached;

		public static Icon Create()
		{
			if (cached != null)
			{
				return cached;
			}
			try
			{
				Bitmap bitmap = new Bitmap(32, 32);
				using (Graphics graphics = Graphics.FromImage(bitmap))
				{
					graphics.SmoothingMode = SmoothingMode.AntiAlias;
					graphics.Clear(Color.Transparent);
					using (SolidBrush brush = new SolidBrush(Color.FromArgb(37, 99, 235)))
					{
						graphics.FillEllipse(brush, 0, 0, 31, 31);
					}
					using (Pen pen = new Pen(Color.White, 2.4f))
					{
						graphics.DrawLine(pen, 8, 12, 24, 12);
						graphics.DrawLine(pen, 8, 20, 24, 20);
						graphics.DrawLine(pen, 16, 6, 16, 26);
					}
				}
				cached = Icon.FromHandle(bitmap.GetHicon());
			}
			catch
			{
			}
			return cached;
		}
	}
	internal class ClientForm : Form
	{
		private ClientConfig cfg;

		private TextBox tbServer;

		private TextBox tbPwd;

		private NumericUpDown numPort;

		private CheckBox chkRemember;

		private CheckBox chkShowPwd;

		private Button btnConnect;

		private Button btnDisconnect;

		private Button btnScan;

		private Button btnTest;

		private Button btnFiles;

		private Button btnChat;

		private Button btnName;

		private Button btnAdvanced;

		private Button btnLock;

		private Label lblStatus;

		private Label lblFooter;

		private Panel pnlStatus;

		private Panel pnlAdvanced;

		private System.Windows.Forms.Timer poll;

		private System.Windows.Forms.Timer banner;

		private System.Windows.Forms.Timer autoScan;

		private bool connected;

		private bool connecting;

		private string connectIp;

		private int connectPort;

		private string lastKey = "";

		private int attempts;

		public bool SelfTestMode;

		private bool scanning;

		private bool allowExit;

		private NotifyIcon tray;

		private readonly LocalRelay relay = new LocalRelay();

		private bool reconnecting;

		public event EventHandler ScanFinished;

		public ClientForm()
		{
			cfg = ClientConfig.Load();
			Text = "NetGate 上网助手";
			base.Size = new Size(640, 650);
			base.StartPosition = FormStartPosition.CenterScreen;
			base.FormBorderStyle = FormBorderStyle.FixedSingle;
			base.MaximizeBox = false;
			Font = new Font("Microsoft YaHei UI", 9f);
			base.AutoScaleMode = AutoScaleMode.None;
			base.Icon = NetGateIcon.Create();
			BuildUiModern();
			UiKit.AddBetaWatermark(this);
			try
			{
				Application.ThreadException += delegate(object s, ThreadExceptionEventArgs e)
				{
					Program.LogFatal("ThreadException", e.Exception);
					MessageBox.Show("程序出错：" + e.Exception.Message, "NetGate 上网助手", MessageBoxButtons.OK, MessageBoxIcon.Hand);
				};
				AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e)
				{
					Program.LogFatal("UnhandledException", e.ExceptionObject as Exception);
				};
			}
			catch
			{
			}
			FileTransferService.UiOwner = this;
			relay.Log = delegate(string m)
			{
				Program.Dbg("relay: " + m);
			};
			if (!Program.SelfTest)
			{
				tray = TrayIcon.Create("NetGate 上网助手（后台运行中）", delegate
				{
					RestoreWindow();
				}, delegate
				{
					ExitApp();
				});
			}
			FileTransferService.ChatArrived += delegate(ChatMessage m)
			{
				try
				{
					if (ChatForm.IsOpen || base.IsDisposed)
					{
						return;
					}
					BeginInvoke((MethodInvoker)delegate
					{
						try
						{
							if (ChatForm.IsOpen)
							{
								return;
							}
							if (tray != null)
							{
								tray.ShowBalloonTip(2500, "NetGate 局域网消息", m.FromName + "：" + m.Text, ToolTipIcon.Info);
							}
						}
						catch
						{
						}
					});
				}
				catch
				{
				}
			};
			base.Load += delegate
			{
				tbServer.Text = cfg.Server;
				numPort.Value = cfg.Port;
				tbPwd.Text = cfg.Password;
				tbPwd.SelectionStart = tbPwd.TextLength;
				tbPwd.SelectionLength = 0;
				chkRemember.Checked = cfg.Remember;
				if (SelfTestMode)
				{
					SetStatus("自检模式。\r\n正在局域网里自动查找控制端……", Color.FromArgb(71, 85, 105));
				}
				else if (string.IsNullOrEmpty(cfg.Password))
				{
					SetStatus("输入管理员给你的授权密码，然后点“开始上网”。\r\n正在自动查找控制端…", Color.FromArgb(37, 99, 235));
				}
				else
				{
					SetStatus("正在自动查找控制端并连接…", Color.FromArgb(37, 99, 235));
				}
				if (!SelfTestMode && string.IsNullOrEmpty(cfg.Password))
				{
					tbPwd.Focus();
				}
				BeginInvoke((MethodInvoker)delegate
				{
					DoScan(true);
				});
			};
			base.FormClosing += delegate(object s, FormClosingEventArgs e)
			{
				Program.Dbg(string.Concat("FormClosing reason=", e.CloseReason, " allowExit=", allowExit, " selftest=", Program.SelfTest));
				if (!allowExit && !Program.SelfTest && (e.CloseReason == CloseReason.UserClosing || e.CloseReason == CloseReason.TaskManagerClosing))
				{
					e.Cancel = true;
					Hide();
					if (tray != null)
					{
						tray.ShowBalloonTip(1500, "NetGate 上网助手", connected ? "已最小化到托盘，代理连接保持。\r\n退出请右键托盘图标。" : "已最小化到托盘，程序在后台运行。\r\n退出请右键托盘图标。", ToolTipIcon.Info);
					}
					return;
				}
				StopSession();
				SaveCfg();
				try
				{
					FileTransferService.StopAll();
				}
				catch
				{
				}
			};
			base.FormClosed += delegate
			{
				try
				{
					if (tray != null)
					{
						tray.Visible = false;
						tray.Dispose();
						tray = null;
					}
				}
				catch
				{
				}
			};
		}

		private void BuildUiOld()
		{
			Panel panel = new Panel();
			panel.Dock = DockStyle.Top;
			panel.Height = 78;
			panel.BackColor = Color.FromArgb(15, 23, 42);
			Panel panel2 = panel;
			base.Controls.Add(panel2);
			panel2.Controls.Add(new Label
			{
				Text = "NetGate 上网助手",
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 15f, FontStyle.Bold),
				Location = new Point(16, 10),
				AutoSize = true
			});
			panel2.Controls.Add(new Label
			{
				Text = "打开后自动找到控制端电脑；输入密码连接，只能用本程序上网",
				ForeColor = Color.FromArgb(148, 163, 184),
				Location = new Point(18, 46),
				AutoSize = true
			});
			base.Controls.Add(new Label
			{
				Text = "控制端地址（自动查找，一般不用改）",
				Location = new Point(20, 92),
				AutoSize = true
			});
			tbServer = new TextBox
			{
				Location = new Point(20, 114),
				Size = new Size(330, 26)
			};
			base.Controls.Add(tbServer);
			base.Controls.Add(new Label
			{
				Text = "端口",
				Location = new Point(362, 92),
				AutoSize = true
			});
			numPort = new NumericUpDown
			{
				Location = new Point(362, 114),
				Size = new Size(70, 26),
				Minimum = 1m,
				Maximum = 65535m,
				Value = 8899m
			};
			base.Controls.Add(numPort);
			btnScan = new Button
			{
				Text = "重新查找",
				Location = new Point(440, 112),
				Size = new Size(96, 28)
			};
			base.Controls.Add(btnScan);
			base.Controls.Add(new Label
			{
				Text = "授权密码（控制端管理员告诉你）",
				Location = new Point(20, 150),
				AutoSize = true
			});
			tbPwd = new TextBox
			{
				Location = new Point(20, 172),
				Size = new Size(330, 26),
				UseSystemPasswordChar = true
			};
			base.Controls.Add(tbPwd);
			chkRemember = new CheckBox
			{
				Text = "记住设置，下次打开自动连接",
				Location = new Point(20, 206),
				Size = new Size(300, 24),
				Checked = true
			};
			base.Controls.Add(chkRemember);
			btnConnect = new Button
			{
				Text = "连接",
				Location = new Point(20, 240),
				Size = new Size(200, 44),
				Font = new Font("Microsoft YaHei UI", 11f, FontStyle.Bold)
			};
			base.Controls.Add(btnConnect);
			btnDisconnect = new Button
			{
				Text = "断开",
				Location = new Point(230, 240),
				Size = new Size(100, 44)
			};
			base.Controls.Add(btnDisconnect);
			btnTest = new Button
			{
				Text = "测速",
				Location = new Point(340, 240),
				Size = new Size(100, 44)
			};
			base.Controls.Add(btnTest);
			Button button = new Button();
			button.Text = "文件传输…";
			button.Location = new Point(20, 292);
			button.Size = new Size(200, 36);
			Button button2 = button;
			button2.Click += delegate
			{
				FileTransferForm.ShowShared(this);
			};
			base.Controls.Add(button2);
			Button button3 = new Button();
			button3.Text = "锁定本机网络(可选)";
			button3.Location = new Point(230, 292);
			button3.Size = new Size(312, 36);
			Button button4 = button3;
			button4.Click += delegate
			{
				if (LocalLock.IsActive())
				{
					LocalLock.Remove();
					MessageBox.Show("已解除本机网络锁定。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				}
				else
				{
					if (!Program.IsAdmin())
					{
						try
						{
							Process.Start(new ProcessStartInfo
							{
								FileName = Program.SelfPath,
								Arguments = "--client --lock",
								UseShellExecute = true,
								Verb = "runas"
							});
							allowExit = true;
							Close();
							return;
						}
						catch
						{
							MessageBox.Show("需要管理员权限才能锁定本机网络。也可以不锁定，直接连接上网。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
							return;
						}
					}
					string[] messages;
					bool flag = LocalLock.Apply(out messages);
					MessageBox.Show(flag ? "已锁定：本机只有本程序能访问外网。\r\n再次点击可解除。" : ("锁定失败：" + string.Join("\r\n", messages)), "NetGate", MessageBoxButtons.OK, flag ? MessageBoxIcon.Asterisk : MessageBoxIcon.Exclamation);
				}
			};
			base.Controls.Add(button4);
			pnlStatus = new Panel
			{
				Location = new Point(16, 340),
				Size = new Size(520, 130),
				BorderStyle = BorderStyle.FixedSingle,
				BackColor = Color.FromArgb(248, 250, 252)
			};
			base.Controls.Add(pnlStatus);
			lblStatus = new Label
			{
				Location = new Point(10, 8),
				Size = new Size(496, 110)
			};
			pnlStatus.Controls.Add(lblStatus);
			SetStatus("正在启动…", Color.FromArgb(71, 85, 105));
			btnConnect.Click += delegate
			{
				DoConnect();
			};
			btnDisconnect.Click += delegate
			{
				StopSession();
				SetStatus("已断开。本机恢复原来的上网设置。", Color.FromArgb(71, 85, 105));
			};
			btnScan.Click += delegate
			{
				DoScan(false);
			};
			btnTest.Click += delegate
			{
				DoSpeedTest();
			};
			poll = new System.Windows.Forms.Timer
			{
				Interval = 2000
			};
			poll.Tick += delegate
			{
				PollStatus();
			};
			banner = new System.Windows.Forms.Timer
			{
				Interval = 800
			};
			banner.Tick += delegate
			{
				try
				{
					string path = Path.Combine(Program.LocalDir, "banner.txt");
					if (File.Exists(path))
					{
						string text = File.ReadAllText(path, Encoding.UTF8);
						File.Delete(path);
						SetStatus(text, Color.FromArgb(185, 28, 28));
					}
				}
				catch
				{
				}
			};
			banner.Start();
		}

		private void BuildUi()
		{
			Panel panel = new Panel();
			panel.Dock = DockStyle.Top;
			panel.Height = 70;
			panel.BackColor = Color.FromArgb(15, 23, 42);
			Panel panel2 = panel;
			base.Controls.Add(panel2);
			panel2.Controls.Add(new Label
			{
				Text = "NetGate 上网助手",
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 16f, FontStyle.Bold),
				Location = new Point(20, 8),
				AutoSize = true
			});
			panel2.Controls.Add(new Label
			{
				Text = "自动找到控制端 · 输入密码即可上网",
				ForeColor = Color.FromArgb(148, 163, 184),
				Location = new Point(20, 42),
				AutoSize = true
			});
			panel2.Controls.Add(new Label
			{
				Text = "关闭窗口后在托盘继续运行",
				ForeColor = Color.FromArgb(100, 116, 139),
				Location = new Point(380, 42),
				AutoSize = true
			});
			pnlStatus = new Panel
			{
				Location = new Point(20, 84),
				Size = new Size(584, 148),
				BackColor = Color.FromArgb(248, 250, 252),
				BorderStyle = BorderStyle.FixedSingle
			};
			base.Controls.Add(pnlStatus);
			lblStatus = new Label
			{
				Location = new Point(18, 12),
				Size = new Size(548, 124),
				Font = new Font("Microsoft YaHei UI", 13.5f, FontStyle.Regular)
			};
			pnlStatus.Controls.Add(lblStatus);
			SetStatus("正在启动…", Color.FromArgb(71, 85, 105));
			base.Controls.Add(new Label
			{
				Text = "授权密码（管理员告诉你）",
				Location = new Point(20, 250),
				AutoSize = true
			});
			tbPwd = new TextBox
			{
				Location = new Point(20, 272),
				Size = new Size(470, 34),
				Font = new Font("Microsoft YaHei UI", 12f),
				UseSystemPasswordChar = true
			};
			base.Controls.Add(tbPwd);
			chkShowPwd = new CheckBox
			{
				Text = "显示",
				Location = new Point(500, 278),
				Size = new Size(90, 24)
			};
			base.Controls.Add(chkShowPwd);
			chkShowPwd.CheckedChanged += delegate
			{
				tbPwd.UseSystemPasswordChar = !chkShowPwd.Checked;
			};
			btnConnect = new Button
			{
				Text = "开始上网",
				Location = new Point(20, 322),
				Size = new Size(584, 56),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.FromArgb(37, 99, 235),
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 13f, FontStyle.Bold),
				Cursor = Cursors.Hand
			};
			btnConnect.FlatAppearance.BorderSize = 0;
			base.Controls.Add(btnConnect);
			btnFiles = new Button
			{
				Text = "文件传输…",
				Location = new Point(20, 390),
				Size = new Size(140, 42),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.White,
				ForeColor = Color.FromArgb(30, 41, 59),
				Font = new Font("Microsoft YaHei UI", 10f)
			};
			btnFiles.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
			base.Controls.Add(btnFiles);
			btnChat = new Button
			{
				Text = "局域网群聊…",
				Location = new Point(166, 390),
				Size = new Size(140, 42),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.White,
				ForeColor = Color.FromArgb(30, 41, 59),
				Font = new Font("Microsoft YaHei UI", 10f)
			};
			btnChat.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
			base.Controls.Add(btnChat);
			btnName = new Button
			{
				Text = "我的名称…",
				Location = new Point(312, 390),
				Size = new Size(140, 42),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.White,
				ForeColor = Color.FromArgb(30, 41, 59),
				Font = new Font("Microsoft YaHei UI", 10f)
			};
			btnName.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
			base.Controls.Add(btnName);
			btnAdvanced = new Button
			{
				Text = "高级设置 ▾",
				Location = new Point(458, 390),
				Size = new Size(146, 42),
				FlatStyle = FlatStyle.Flat,
				BackColor = Color.White,
				ForeColor = Color.FromArgb(30, 41, 59),
				Font = new Font("Microsoft YaHei UI", 10f)
			};
			btnAdvanced.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
			base.Controls.Add(btnAdvanced);
			pnlAdvanced = new Panel
			{
				Location = new Point(20, 444),
				Size = new Size(584, 132),
				BackColor = Color.FromArgb(248, 250, 252),
				BorderStyle = BorderStyle.FixedSingle,
				Visible = false
			};
			base.Controls.Add(pnlAdvanced);
			pnlAdvanced.Controls.Add(new Label
			{
				Text = "控制端地址",
				Location = new Point(12, 10),
				AutoSize = true
			});
			tbServer = new TextBox
			{
				Location = new Point(92, 6),
				Size = new Size(250, 26)
			};
			pnlAdvanced.Controls.Add(tbServer);
			pnlAdvanced.Controls.Add(new Label
			{
				Text = "端口",
				Location = new Point(352, 10),
				AutoSize = true
			});
			numPort = new NumericUpDown
			{
				Location = new Point(392, 6),
				Size = new Size(70, 26),
				Minimum = 1m,
				Maximum = 65535m,
				Value = 8899m
			};
			pnlAdvanced.Controls.Add(numPort);
			btnScan = new Button
			{
				Text = "自动查找",
				Location = new Point(472, 4),
				Size = new Size(98, 30)
			};
			pnlAdvanced.Controls.Add(btnScan);
			chkRemember = new CheckBox
			{
				Text = "记住密码，下次打开自动连接",
				Location = new Point(12, 44),
				Size = new Size(300, 24),
				Checked = true
			};
			pnlAdvanced.Controls.Add(chkRemember);
			btnTest = new Button
			{
				Text = "测速",
				Location = new Point(12, 78),
				Size = new Size(110, 34)
			};
			pnlAdvanced.Controls.Add(btnTest);
			btnLock = new Button
			{
				Text = "锁定本机网络(可选)",
				Location = new Point(132, 78),
				Size = new Size(190, 34)
			};
			pnlAdvanced.Controls.Add(btnLock);
			pnlAdvanced.Controls.Add(new Label
			{
				Text = "锁定会阻断其它程序出网，\r\n需要局域网共享时不要开。",
				Location = new Point(334, 76),
				Size = new Size(240, 40),
				ForeColor = Color.FromArgb(100, 116, 139)
			});
			Label tip = new Label
			{
				Location = new Point(20, 468),
				Size = new Size(584, 70),
				ForeColor = Color.FromArgb(100, 116, 139),
				Text = "第一次使用：确认“授权密码”已填好，点上面的“开始上网”。\r\n连不上时点“高级设置”手动填写控制端地址，或点“自动查找”。"
			};
			base.Controls.Add(tip);
			lblFooter = new Label
			{
				Text = "关闭窗口 = 收起到托盘后台运行；彻底退出请右键托盘图标 → 退出",
				Location = new Point(20, 560),
				AutoSize = true,
				ForeColor = Color.FromArgb(148, 163, 184)
			};
			base.Controls.Add(lblFooter);
			btnConnect.Click += delegate
			{
				if (connected)
				{
					StopSession();
					SetStatus("已断开。本机恢复原来的上网设置。", Color.FromArgb(71, 85, 105));
				}
				else if (lastKey == "pending")
				{
					StopSession();
					SetStatus("已取消等待管理员允许。", Color.FromArgb(71, 85, 105));
				}
				else
				{
					DoConnect();
				}
			};
			btnFiles.Click += delegate
			{
				FileTransferForm.ShowShared(this);
			};
			btnChat.Click += delegate
			{
				ChatForm.ShowShared(this);
			};
			btnName.Click += delegate
			{
				string text = NameDialog.Show(this, FileTransferService.Current.LocalName);
				if (!string.IsNullOrEmpty(text))
				{
					FileTransferService.Current.SetLocalName(text);
					SetStatus("名称已改为：" + FileTransferService.Current.LocalName + "\r\n对方重新扫描即可看到；控制端几秒内刷新。", Color.FromArgb(71, 85, 105));
				}
			};
			btnAdvanced.Click += delegate
			{
				pnlAdvanced.Visible = !pnlAdvanced.Visible;
				tip.Visible = !pnlAdvanced.Visible;
				lblFooter.Visible = !pnlAdvanced.Visible;
				btnAdvanced.Text = (pnlAdvanced.Visible ? "收起高级设置 ▴" : "高级设置 ▾");
			};
			btnScan.Click += delegate
			{
				DoScan(false);
			};
			btnTest.Click += delegate
			{
				DoSpeedTest();
			};
			btnLock.Click += delegate
			{
				if (LocalLock.IsActive())
				{
					LocalLock.Remove();
					MessageBox.Show("已解除本机网络锁定。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				}
				else
				{
					if (!Program.IsAdmin())
					{
						try
						{
							Process.Start(new ProcessStartInfo
							{
								FileName = Program.SelfPath,
								Arguments = "--client --lock",
								UseShellExecute = true,
								Verb = "runas"
							});
							allowExit = true;
							Close();
							return;
						}
						catch
						{
							MessageBox.Show("需要管理员权限才能锁定本机网络。也可以不锁定，直接连接上网。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
							return;
						}
					}
					string[] messages;
					bool flag = LocalLock.Apply(out messages);
					MessageBox.Show(flag ? "已锁定：本机只有本程序能访问外网。\r\n再次点击可解除。" : ("锁定失败：" + string.Join("\r\n", messages)), "NetGate", MessageBoxButtons.OK, flag ? MessageBoxIcon.Asterisk : MessageBoxIcon.Exclamation);
				}
			};
			poll = new System.Windows.Forms.Timer
			{
				Interval = 2000
			};
			poll.Tick += delegate
			{
				PollStatus();
			};
			banner = new System.Windows.Forms.Timer
			{
				Interval = 800
			};
			banner.Tick += delegate
			{
				try
				{
					string path = Path.Combine(Program.LocalDir, "banner.txt");
					if (File.Exists(path))
					{
						string text = File.ReadAllText(path, Encoding.UTF8);
						File.Delete(path);
						SetStatus(text, Color.FromArgb(185, 28, 28));
					}
				}
				catch
				{
				}
			};
			banner.Start();
			autoScan = new System.Windows.Forms.Timer
			{
				Interval = 20000
			};
			autoScan.Tick += delegate
			{
				if (!connected && !connecting && !scanning && lastKey != "pending" && string.IsNullOrEmpty(tbServer.Text.Trim()))
				{
					DoScan(true);
				}
			};
			autoScan.Start();
			UpdateMainButton();
		}

		private void UpdateMainButton()
		{
			bool locked = connected || connecting || lastKey == "pending";
			if (tbPwd != null)
			{
				tbPwd.Enabled = !locked;
			}
			if (tbServer != null)
			{
				tbServer.Enabled = !locked;
			}
			if (numPort != null)
			{
				numPort.Enabled = !locked;
			}
			if (chkRemember != null)
			{
				chkRemember.Enabled = !connected;
			}
			if (btnConnect != null)
			{
				Color mouseOver;
				Color mouseDown;
				if (connected)
				{
					btnConnect.Text = "断开上网";
					btnConnect.BackColor = Color.FromArgb(220, 38, 38);
					mouseOver = Color.FromArgb(185, 28, 28);
					mouseDown = Color.FromArgb(153, 27, 27);
					btnConnect.Enabled = true;
				}
				else if (connecting)
				{
					btnConnect.Text = "连接中…";
					btnConnect.BackColor = Color.FromArgb(148, 163, 184);
					mouseOver = Color.FromArgb(148, 163, 184);
					mouseDown = Color.FromArgb(148, 163, 184);
					btnConnect.Enabled = false;
				}
				else if (lastKey == "pending")
				{
					btnConnect.Text = "取消等待（管理员允许后自动连接）";
					btnConnect.BackColor = Color.FromArgb(217, 119, 6);
					mouseOver = Color.FromArgb(180, 83, 9);
					mouseDown = Color.FromArgb(146, 64, 14);
					btnConnect.Enabled = true;
				}
				else
				{
					btnConnect.Text = "开始上网";
					btnConnect.BackColor = Color.FromArgb(37, 99, 235);
					mouseOver = UiKit.PrimaryDark;
					mouseDown = Color.FromArgb(30, 64, 175);
					btnConnect.Enabled = true;
				}
				btnConnect.FlatAppearance.MouseOverBackColor = mouseOver;
				btnConnect.FlatAppearance.MouseDownBackColor = mouseDown;
			}
		}

		private void SetStatus(string text, Color color)
		{
			if (lblStatus != null)
			{
				lblStatus.Text = text;
				lblStatus.ForeColor = color;
			}
			UpdateMainButton();
		}

		private void SaveCfg()
		{
			cfg.Server = tbServer.Text.Trim();
			cfg.Port = (int)numPort.Value;
			cfg.Password = (chkRemember.Checked ? tbPwd.Text : "");
			cfg.Remember = chkRemember.Checked;
			cfg.Save();
		}

		private void DoScan(bool automatic)
		{
			if (scanning)
			{
				return;
			}
			scanning = true;
			btnScan.Enabled = false;
			int port = (int)numPort.Value;
			string savedServer = tbServer.Text.Trim();
			SetStatus(automatic ? "正在查找控制端…（几秒钟）" : "正在扫描局域网…（几秒钟）", Color.FromArgb(37, 99, 235));
			Thread thread = new Thread((ThreadStart)delegate
			{
				string found = null;
				try
				{
					if (!string.IsNullOrEmpty(savedServer) && Probe(savedServer, port, 1200))
					{
						found = savedServer;
					}
					if (found == null)
					{
						List<string> prefixes = Util.LanPrefixes();
						string self = Util.LanIPv4();
						List<string> candidates = new List<string>();
						foreach (string prefix in prefixes)
						{
							for (int i = 1; i <= 254; i++)
							{
								string ip = prefix + "." + i;
								if (ip != self)
								{
									candidates.Add(ip);
								}
							}
						}
						Program.Dbg("scan prefixes=" + prefixes.Count + " candidates=" + candidates.Count);
						string[] answer = new string[1];
						Stopwatch scanWatch = Stopwatch.StartNew();
						int cursor = -1;
						int workerCount = Math.Min(64, candidates.Count);
						Thread[] workers = new Thread[workerCount];
						for (int w = 0; w < workerCount; w++)
						{
							Thread worker = new Thread((ThreadStart)delegate
							{
								while (answer[0] == null && scanWatch.ElapsedMilliseconds <= 9000)
								{
									int index = Interlocked.Increment(ref cursor);
									if (index >= candidates.Count)
									{
										break;
									}
									string ip = candidates[index];
									if (Probe(ip, port, 600))
									{
										Interlocked.CompareExchange(ref answer[0], ip, null);
									}
								}
							});
							worker.IsBackground = true;
							workers[w] = worker;
							worker.Start();
						}
						foreach (Thread worker in workers)
						{
							worker.Join();
						}
						found = answer[0];
						Program.Dbg("scan done found=" + ((found == null) ? "none" : found) + " ms=" + scanWatch.ElapsedMilliseconds);
					}
				}
				catch
				{
				}
				BeginInvoke((MethodInvoker)delegate
				{
					scanning = false;
					btnScan.Enabled = true;
					try
					{
						if (this.ScanFinished != null)
						{
							this.ScanFinished(this, EventArgs.Empty);
						}
					}
					catch
					{
					}
					if (found != null)
					{
						tbServer.Text = found;
						if (cfg.Remember && !string.IsNullOrEmpty(cfg.Password) && !connected)
						{
							SetStatus("已找到控制端：" + found + "\r\n正在用记住的密码自动连接…", Color.FromArgb(37, 99, 235));
							DoConnect();
						}
						else
						{
							SetStatus("已找到控制端：" + found + "\r\n请输入授权密码，然后点“开始上网”。", Color.FromArgb(22, 101, 52));
						}
					}
					else
					{
						SetStatus("没有自动找到控制端。\r\n请确认：\r\n• 控制端正在运行，且防火墙已放行 8899\r\n• 两台电脑在同一网段\r\n也可以在“高级设置”里手动填写控制端地址后点“开始上网”。", Color.FromArgb(185, 28, 28));
					}
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private static bool LooksLikeNetGate(string text)
		{
			if (string.IsNullOrEmpty(text))
			{
				return false;
			}
			if (text.IndexOf("NetGate", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return true;
			}
			if (text.IndexOf("\"ok\":true", StringComparison.Ordinal) >= 0)
			{
				return text.IndexOf("\"onlineCount\"", StringComparison.Ordinal) >= 0;
			}
			return false;
		}

		private static bool Probe(string ip, int port, int timeoutMs)
		{
			try
			{
				using (TcpClient tcpClient = new TcpClient())
				{
					IAsyncResult asyncResult = tcpClient.BeginConnect(ip, port, null, null);
					if (!asyncResult.AsyncWaitHandle.WaitOne(timeoutMs))
					{
						return false;
					}
					tcpClient.EndConnect(asyncResult);
					tcpClient.ReceiveTimeout = timeoutMs;
					NetworkStream stream = tcpClient.GetStream();
					byte[] bytes = Encoding.ASCII.GetBytes("GET /__netgate/hello?mac=" + Util.MachineId() + "&name=" + Util.Q(Environment.MachineName) + "&user=" + Util.Q(Environment.UserName) + "&v=1.0 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
					stream.Write(bytes, 0, bytes.Length);
					stream.Flush();
					byte[] array = new byte[1024];
					int num = stream.Read(array, 0, array.Length);
					return num > 0 && LooksLikeNetGate(Encoding.UTF8.GetString(array, 0, num));
				}
			}
			catch
			{
				return false;
			}
		}

		private void DoConnect()
		{
			string server = tbServer.Text.Trim();
			string pwd = tbPwd.Text;
			int port = (int)numPort.Value;
			if (server.Length == 0)
			{
				MessageBox.Show("还没有找到控制端地址，请先等一下自动扫描，或填写控制端窗口顶部显示的“网关地址”。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
				return;
			}
			if (pwd.Length == 0)
			{
				MessageBox.Show("请输入授权密码（控制端管理员设置的密码）。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
				tbPwd.Focus();
				return;
			}
			connecting = true;
			SetStatus("正在连接 " + server + ":" + port + " …", Color.FromArgb(37, 99, 235));
			string ip = server;
			string mac = Util.MachineId();
			Thread thread = new Thread((ThreadStart)delegate
			{
				string err = null;
				ProxyResult vr = null;
				try
				{
					ProxyTalk.Status(ip, port, mac, Environment.MachineName, Environment.UserName, 4000);
					vr = ProxyTalk.Verify(ip, port, mac, pwd, 8000);
				}
				catch (Exception ex)
				{
					err = ex.Message;
				}
				BeginInvoke((MethodInvoker)delegate
				{
					connecting = false;
					if (err != null || vr == null)
					{
						SetStatus("连不上控制端 " + server + ":" + port + "。\r\n请检查：1) 地址/端口是否正确 2) 两台电脑是否在同一局域网 3) 对方控制端是否正在运行", Color.FromArgb(185, 28, 28));
					}
					else
					{
						try
						{
							if (vr.Client != null)
							{
								vr.Client.Close();
							}
						}
						catch
						{
						}
						if (vr.Code == 200)
						{
							StartSession(ip, port, pwd);
						}
						else if (vr.Code == 403 && vr.Key == "pending")
						{
							attempts = 0;
							lastKey = "pending";
							connectIp = ip;
							connectPort = port;
							connected = false;
							SetStatus("密码正确，已把本机登记到控制端。\r\n等待控制端管理员点“允许上网”……（会自动继续）", Color.FromArgb(180, 83, 9));
							poll.Start();
						}
						else if (vr.Code == 407)
						{
							SetStatus("密码不正确，请向管理员确认授权密码。", Color.FromArgb(185, 28, 28));
						}
						else
						{
							SetStatus("连接失败（" + vr.Code + " " + vr.Key + "）。请确认控制端已启动。", Color.FromArgb(185, 28, 28));
						}
					}
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private void StartSession(string ip, int port, string pwd)
		{
			int boundPort;
			string error;
			if (!relay.Start(ip, port, Util.MachineId(), pwd, out boundPort, out error))
			{
				connected = false;
				SetStatus("本机转发代理启动失败：" + error + "\r\n请检查端口是否被安全软件拦截。", Color.FromArgb(185, 28, 28));
				return;
			}
			SaveCfg();
			connected = true;
			connecting = false;
			connectIp = ip;
			connectPort = port;
			lastKey = "";
			SystemProxy.Apply("127.0.0.1", boundPort);
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append("已连接！现在可以通过控制端上网。");
			stringBuilder.Append(Environment.NewLine);
			stringBuilder.Append("控制端：").Append(ip).Append(':')
				.Append(port);
			stringBuilder.Append(Environment.NewLine);
			stringBuilder.Append("本机转发代理：127.0.0.1:").Append(boundPort);
			stringBuilder.Append(Environment.NewLine);
			if (LocalLock.IsActive())
			{
				stringBuilder.Append("本机网络已锁定：只有本程序能把数据送到控制端。");
			}
			else
			{
				stringBuilder.Append("浏览器已自动设置好代理，可直接打开网页。");
			}
			SetStatus(stringBuilder.ToString(), Color.FromArgb(22, 101, 52));
			poll.Start();
			PollStatus();
		}

		private void StopSession()
		{
			connected = false;
			connecting = false;
			lastKey = "";
			try
			{
				poll.Stop();
			}
			catch
			{
			}
			SystemProxy.Restore();
			relay.Stop();
			if (LocalLock.IsActive())
			{
				LocalLock.Remove();
			}
			UpdateMainButton();
		}

		private void PollStatus()
		{
			if (connected)
			{
				string ip = connectIp;
				int port = connectPort;
				string mac = Util.MachineId();
				Thread thread = new Thread((ThreadStart)delegate
				{
					string text2 = ProxyTalk.Status(ip, port, mac, Environment.MachineName, Environment.UserName, 3000);
					int online = 0;
					string status;
					if (text2 == null)
					{
						status = "down";
					}
					else
					{
						online = (int)Util.AsLong(Util.JsonField(text2, "onlineCount"));
						bool flag = Util.AsBool(Util.JsonField(text2, "kicked"));
						bool flag2 = Util.AsBool(Util.JsonField(text2, "allowed"));
						bool flag3 = Util.AsBool(Util.JsonField(text2, "paused"));
						status = ((flag || !flag2) ? "denied" : (flag3 ? "paused" : "ok"));
					}
					BeginInvoke((MethodInvoker)delegate
					{
						if (connected)
						{
							if (status == "down")
							{
								Reconnect(ip, port);
							}
							else if (status == "denied")
							{
								SetStatus("控制端已断开本机的上网权限。\r\n请联系管理员重新允许上网。", Color.FromArgb(185, 28, 28));
								StopSession();
							}
							else if (status == "paused")
							{
								SetStatus("控制端已暂停本机上网。\r\n管理员点“恢复”后会自动继续。", Color.FromArgb(180, 83, 9));
							}
							else
							{
								bool flag4 = LocalLock.IsActive();
								SetStatus("已连接，可以通过控制端上网。\r\n控制端：" + ip + ":" + port + "\r\n当前在线设备：" + online + " 台\r\n" + (flag4 ? "本机网络已锁定：只有本程序能通外网。" : "浏览器已自动设置代理，可直接打开网页。"), Color.FromArgb(22, 101, 52));
							}
						}
					});
				});
				thread.IsBackground = true;
				thread.Start();
			}
			else
			{
				if (!(lastKey == "pending"))
				{
					return;
				}
				string ip2 = connectIp;
				int port2 = connectPort;
				string mac2 = Util.MachineId();
				Thread thread2 = new Thread((ThreadStart)delegate
				{
					string text = ProxyTalk.Status(ip2, port2, mac2, Environment.MachineName, Environment.UserName, 3000);
					bool allowed = text != null && Util.AsBool(Util.JsonField(text, "allowed"));
					BeginInvoke((MethodInvoker)delegate
					{
						if (allowed)
						{
							lastKey = "";
							try
							{
								poll.Stop();
							}
							catch
							{
							}
							SetStatus("控制端已允许本机上网，正在连接…", Color.FromArgb(37, 99, 235));
							DoConnect();
						}
						else
						{
							attempts++;
							SetStatus("密码正确，已把本机登记到控制端。\r\n等待控制端管理员点“允许上网”……（第 " + attempts + " 次检查）", Color.FromArgb(180, 83, 9));
						}
					});
				});
				thread2.IsBackground = true;
				thread2.Start();
			}
		}

		private void Reconnect(string ip, int port)
		{
			if (reconnecting)
			{
				return;
			}
			reconnecting = true;
			string mac = Util.MachineId();
			string pwd = tbPwd.Text;
			Thread thread = new Thread((ThreadStart)delegate
			{
				ProxyResult vr = null;
				try
				{
					vr = ProxyTalk.Verify(ip, port, mac, pwd, 5000);
				}
				catch
				{
				}
				BeginInvoke((MethodInvoker)delegate
				{
					reconnecting = false;
					if (vr != null)
					{
						try
						{
							if (vr.Client != null)
							{
								vr.Client.Close();
							}
						}
						catch
						{
						}
						if (vr.Code == 200)
						{
							SetStatus("已重新连上控制端。", Color.FromArgb(22, 101, 52));
						}
						else
						{
							SetStatus("与控制端的连接中断了，正在自动重试…\r\n（检查对方控制端是否被关闭、两台电脑是否还在同一局域网）", Color.FromArgb(185, 28, 28));
						}
					}
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private void RestoreWindow()
		{
			Show();
			if (base.WindowState == FormWindowState.Minimized)
			{
				base.WindowState = FormWindowState.Normal;
			}
			base.ShowInTaskbar = true;
			Activate();
			BringToFront();
		}

		private void ExitApp()
		{
			allowExit = true;
			Close();
		}

		private void DoSpeedTest()
		{
			if (!connected)
			{
				MessageBox.Show("请先点“连接”，连上之后再测速。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			btnTest.Enabled = false;
			SetStatus("正在测速（约 6 秒）…", Color.FromArgb(37, 99, 235));
			string ip = connectIp;
			int port = connectPort;
			string mac = Util.MachineId();
			string pwd = tbPwd.Text;
			Thread thread = new Thread((ThreadStart)delegate
			{
				long bytes = 0L;
				double secs = 1.0;
				try
				{
					try
					{
						ProxyResult proxyResult = ProxyTalk.Connect(ip, port, mac, pwd, "speed.cloudflare.com:443", "CONNECT", null, 6000);
						if (proxyResult.Code == 200 && proxyResult.Stream != null)
						{
							byte[] bytes2 = Encoding.ASCII.GetBytes("GET /__down?bytes=20000000 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n");
							proxyResult.Stream.Write(bytes2, 0, bytes2.Length);
							proxyResult.Stream.Flush();
							proxyResult.Client.ReceiveTimeout = 4000;
							byte[] array = new byte[16384];
							Stopwatch stopwatch = Stopwatch.StartNew();
							while (stopwatch.ElapsedMilliseconds < 6000)
							{
								int num;
								try
								{
									num = proxyResult.Stream.Read(array, 0, array.Length);
								}
								catch
								{
									break;
								}
								if (num <= 0)
								{
									break;
								}
								bytes += num;
							}
							secs = Math.Max(0.5, stopwatch.Elapsed.TotalSeconds);
							try
							{
								proxyResult.Client.Close();
							}
							catch
							{
							}
						}
					}
					catch
					{
					}
				}
				catch (Exception ex)
				{
					Program.LogFatal("SpeedTest", ex);
				}
				BeginInvoke((MethodInvoker)delegate
				{
					btnTest.Enabled = true;
					SetStatus("测速结果：约 " + Util.FmtRate((double)bytes / secs) + "\r\n（共下载 " + Util.FmtBytes(bytes) + "，用时 " + secs.ToString("0.0") + " 秒）", Color.FromArgb(22, 101, 52));
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private void BuildUiModern()
		{
			SuspendLayout();
			UiKit.Apply(this);
			DoubleBuffered = true;
			Text = "NetGate 上网助手";
			base.Size = new Size(680, 610);
			BackColor = UiKit.Bg;

			TableLayoutPanel root = new TableLayoutPanel();
			root.Dock = DockStyle.Fill;
			root.ColumnCount = 1;
			root.RowCount = 3;
			root.BackColor = UiKit.Bg;
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64f));
			root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
			base.Controls.Add(root);

			Panel header = new Panel();
			header.Dock = DockStyle.Fill;
			header.BackColor = UiKit.Header;
			root.Controls.Add(header, 0, 0);
			header.Controls.Add(new Label
			{
				Text = "NetGate 上网助手",
				ForeColor = Color.White,
				Font = UiKit.Title,
				AutoSize = true,
				Location = new Point(20, 18)
			});
			FlowLayoutPanel headerRight = new FlowLayoutPanel();
			headerRight.Dock = DockStyle.Right;
			headerRight.Width = 360;
			headerRight.FlowDirection = FlowDirection.RightToLeft;
			headerRight.WrapContents = false;
			headerRight.BackColor = UiKit.Header;
			headerRight.Padding = new Padding(0, 22, 20, 0);
			header.Controls.Add(headerRight);
			Label headerHint = new Label();
			headerHint.Text = "安全 · 局域网直连";
			headerHint.ForeColor = UiKit.HeaderText;
			headerHint.Font = UiKit.Body;
			headerHint.AutoSize = true;
			headerHint.Margin = new Padding(0);
			headerRight.Controls.Add(headerHint);

			Panel body = new Panel();
			body.Dock = DockStyle.Fill;
			body.BackColor = UiKit.Bg;
			body.Padding = new Padding(16, 16, 16, 12);
			root.Controls.Add(body, 0, 1);

			TableLayoutPanel stack = new TableLayoutPanel();
			stack.Dock = DockStyle.Fill;
			stack.ColumnCount = 1;
			stack.RowCount = 6;
			stack.BackColor = UiKit.Bg;
			stack.RowStyles.Add(new RowStyle(SizeType.Absolute, 140f));
			stack.RowStyles.Add(new RowStyle(SizeType.Absolute, 132f));
			stack.RowStyles.Add(new RowStyle(SizeType.Absolute, 64f));
			stack.RowStyles.Add(new RowStyle(SizeType.Absolute, 60f));
			RowStyle advancedRow = new RowStyle(SizeType.Absolute, 0f);
			stack.RowStyles.Add(advancedRow);
			stack.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			body.Controls.Add(stack);

			pnlStatus = UiKit.CardPanel();
			pnlStatus.Dock = DockStyle.Fill;
			pnlStatus.Margin = new Padding(0, 0, 0, 12);
			pnlStatus.Padding = new Padding(18, 14, 18, 12);
			stack.Controls.Add(pnlStatus, 0, 0);

			lblStatus = new Label();
			lblStatus.Dock = DockStyle.Fill;
			lblStatus.AutoSize = false;
			lblStatus.AutoEllipsis = true;
			lblStatus.TextAlign = ContentAlignment.TopLeft;
			lblStatus.Font = new Font("Microsoft YaHei UI", 10.5f);
			lblStatus.ForeColor = UiKit.Muted;
			pnlStatus.Controls.Add(lblStatus);
			SetStatus("正在启动…", Color.FromArgb(71, 85, 105));

			Panel pwdCard = UiKit.CardPanel();
			pwdCard.Dock = DockStyle.Fill;
			pwdCard.Margin = new Padding(0, 0, 0, 12);
			pwdCard.Padding = new Padding(18, 12, 18, 12);
			stack.Controls.Add(pwdCard, 0, 1);

			TableLayoutPanel pwdLayout = new TableLayoutPanel();
			pwdLayout.Dock = DockStyle.Fill;
			pwdLayout.ColumnCount = 1;
			pwdLayout.RowCount = 2;
			pwdLayout.BackColor = UiKit.Card;
			pwdLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
			pwdLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			pwdCard.Controls.Add(pwdLayout);
			pwdLayout.Controls.Add(new Label
			{
				Text = "授权密码",
				Font = UiKit.SubTitle,
				ForeColor = UiKit.TextColor,
				AutoSize = true,
				Margin = new Padding(0)
			}, 0, 0);

			TableLayoutPanel pwdRow = new TableLayoutPanel();
			pwdRow.Dock = DockStyle.Fill;
			pwdRow.ColumnCount = 2;
			pwdRow.RowCount = 1;
			pwdRow.BackColor = UiKit.Card;
			pwdRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
			pwdRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 86f));
			pwdLayout.Controls.Add(pwdRow, 0, 1);

			tbPwd = new TextBox();
			tbPwd.Dock = DockStyle.Fill;
			tbPwd.Font = new Font("Microsoft YaHei UI", 12f);
			tbPwd.UseSystemPasswordChar = true;
			tbPwd.BorderStyle = BorderStyle.FixedSingle;
			tbPwd.Margin = new Padding(0, 4, 12, 0);
			pwdRow.Controls.Add(tbPwd, 0, 0);

			chkShowPwd = new CheckBox();
			chkShowPwd.Text = "显示";
			chkShowPwd.AutoSize = true;
			chkShowPwd.ForeColor = UiKit.Muted;
			chkShowPwd.Margin = new Padding(0, 10, 0, 0);
			pwdRow.Controls.Add(chkShowPwd, 1, 0);

			btnConnect = UiKit.PrimaryButton("开始上网");
			btnConnect.Dock = DockStyle.Fill;
			btnConnect.Font = new Font("Microsoft YaHei UI", 12f, FontStyle.Bold);
			btnConnect.Margin = new Padding(0, 0, 0, 12);
			stack.Controls.Add(btnConnect, 0, 2);

			TableLayoutPanel actions = new TableLayoutPanel();
			actions.Dock = DockStyle.Fill;
			actions.ColumnCount = 4;
			actions.RowCount = 1;
			actions.BackColor = UiKit.Bg;
			actions.Margin = new Padding(0);
			for (int i = 0; i < 4; i++)
			{
				actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25f));
			}
			stack.Controls.Add(actions, 0, 3);

			btnFiles = UiKit.SecondaryButton("文件传输");
			btnFiles.Dock = DockStyle.Fill;
			btnFiles.Margin = new Padding(0, 0, 8, 12);
			actions.Controls.Add(btnFiles, 0, 0);
			btnChat = UiKit.SecondaryButton("局域网群聊");
			btnChat.Dock = DockStyle.Fill;
			btnChat.Margin = new Padding(0, 0, 8, 12);
			actions.Controls.Add(btnChat, 1, 0);
			btnName = UiKit.SecondaryButton("我的名称");
			btnName.Dock = DockStyle.Fill;
			btnName.Margin = new Padding(0, 0, 8, 12);
			actions.Controls.Add(btnName, 2, 0);
			btnAdvanced = UiKit.SecondaryButton("高级设置");
			btnAdvanced.Dock = DockStyle.Fill;
			btnAdvanced.Margin = new Padding(0, 0, 0, 12);
			actions.Controls.Add(btnAdvanced, 3, 0);

			pnlAdvanced = UiKit.CardPanel();
			pnlAdvanced.Dock = DockStyle.Fill;
			pnlAdvanced.Margin = new Padding(0, 12, 0, 0);
			pnlAdvanced.Padding = new Padding(18, 12, 18, 12);
			pnlAdvanced.Visible = false;
			stack.Controls.Add(pnlAdvanced, 0, 4);

			TableLayoutPanel advLayout = new TableLayoutPanel();
			advLayout.Dock = DockStyle.Fill;
			advLayout.ColumnCount = 1;
			advLayout.RowCount = 3;
			advLayout.BackColor = UiKit.Card;
			advLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40f));
			advLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36f));
			advLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36f));
			pnlAdvanced.Controls.Add(advLayout);

			FlowLayoutPanel addressRow = new FlowLayoutPanel();
			addressRow.Dock = DockStyle.Fill;
			addressRow.FlowDirection = FlowDirection.LeftToRight;
			addressRow.WrapContents = false;
			addressRow.BackColor = UiKit.Card;
			addressRow.Margin = new Padding(0);
			advLayout.Controls.Add(addressRow, 0, 0);
			addressRow.Controls.Add(UiKit.FieldLabel("控制端地址"));
			tbServer = new TextBox();
			tbServer.Width = 190;
			tbServer.BorderStyle = BorderStyle.FixedSingle;
			tbServer.Margin = new Padding(8, 6, 16, 0);
			addressRow.Controls.Add(tbServer);
			Label portLabel = UiKit.FieldLabel("端口");
			portLabel.Margin = new Padding(0, 8, 8, 0);
			addressRow.Controls.Add(portLabel);
			numPort = new NumericUpDown();
			numPort.Width = 76;
			numPort.Minimum = 1m;
			numPort.Maximum = 65535m;
			numPort.Value = 8899m;
			numPort.Margin = new Padding(0, 4, 12, 0);
			addressRow.Controls.Add(numPort);
			btnScan = UiKit.SecondaryButton("自动查找");
			btnScan.Width = 92;
			btnScan.Margin = new Padding(0, 2, 0, 0);
			addressRow.Controls.Add(btnScan);

			chkRemember = new CheckBox();
			chkRemember.Text = "记住密码，下次自动连接";
			chkRemember.AutoSize = true;
			chkRemember.Checked = true;
			chkRemember.ForeColor = UiKit.TextColor;
			chkRemember.Margin = new Padding(0, 8, 0, 0);
			advLayout.Controls.Add(chkRemember, 0, 1);

			FlowLayoutPanel advActions = new FlowLayoutPanel();
			advActions.Dock = DockStyle.Fill;
			advActions.FlowDirection = FlowDirection.LeftToRight;
			advActions.WrapContents = false;
			advActions.BackColor = UiKit.Card;
			advActions.Margin = new Padding(0);
			advLayout.Controls.Add(advActions, 0, 2);
			btnTest = UiKit.SecondaryButton("测速");
			btnTest.Width = 80;
			advActions.Controls.Add(btnTest);
			btnLock = UiKit.SecondaryButton("锁定本机网络");
			btnLock.Width = 112;
			advActions.Controls.Add(btnLock);

			lblFooter = new Label();
			lblFooter.Text = "数据仅在本机与局域网内传输";
			Panel status = UiKit.StatusBar(lblFooter);
			root.Controls.Add(status, 0, 2);

			ToolTip tips = new ToolTip();
			tips.SetToolTip(btnAdvanced, "手动填写控制端地址、端口，或锁定本机网络。");
			tips.SetToolTip(btnLock, "锁定会阻断其它程序出网，需要局域网共享时不要开启。");
			tips.SetToolTip(btnChat, "向局域网内所有 NetGate 电脑发送文字消息。");
			tips.SetToolTip(btnFiles, "与局域网内的 NetGate 电脑互相发送文件。");

			btnConnect.Click += delegate
			{
				if (connected)
				{
					StopSession();
					SetStatus("已断开。本机恢复原来的上网设置。", Color.FromArgb(71, 85, 105));
				}
				else if (lastKey == "pending")
				{
					StopSession();
					SetStatus("已取消等待管理员允许。", Color.FromArgb(71, 85, 105));
				}
				else
				{
					DoConnect();
				}
			};
			btnFiles.Click += delegate
			{
				FileTransferForm.ShowShared(this);
			};
			btnChat.Click += delegate
			{
				ChatForm.ShowShared(this);
			};
			btnName.Click += delegate
			{
				string text = NameDialog.Show(this, FileTransferService.Current.LocalName);
				if (!string.IsNullOrEmpty(text))
				{
					FileTransferService.Current.SetLocalName(text);
					SetStatus("名称已改为：" + FileTransferService.Current.LocalName, Color.FromArgb(71, 85, 105));
				}
			};
			btnAdvanced.Click += delegate
			{
				bool show = !pnlAdvanced.Visible;
				pnlAdvanced.Visible = show;
				advancedRow.Height = (show ? 164f : 0f);
				btnAdvanced.Text = (show ? "收起设置" : "高级设置");
				base.Height = (show ? 780 : 610);
			};
			btnScan.Click += delegate
			{
				DoScan(false);
			};
			btnTest.Click += delegate
			{
				DoSpeedTest();
			};
			btnLock.Click += delegate
			{
				if (LocalLock.IsActive())
				{
					LocalLock.Remove();
					MessageBox.Show("已解除本机网络锁定。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				}
				else
				{
					if (!Program.IsAdmin())
					{
						try
						{
							Process.Start(new ProcessStartInfo
							{
								FileName = Program.SelfPath,
								Arguments = "--client --lock",
								UseShellExecute = true,
								Verb = "runas"
							});
							allowExit = true;
							Close();
							return;
						}
						catch
						{
							MessageBox.Show("需要管理员权限才能锁定本机网络。也可以不锁定，直接连接上网。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
							return;
						}
					}
					string[] messages;
					bool flag = LocalLock.Apply(out messages);
					MessageBox.Show(flag ? "已锁定：本机只有本程序能访问外网。\r\n再次点击可解除。" : ("锁定失败：" + string.Join("\r\n", messages)), "NetGate", MessageBoxButtons.OK, flag ? MessageBoxIcon.Asterisk : MessageBoxIcon.Exclamation);
				}
			};
			chkShowPwd.CheckedChanged += delegate
			{
				tbPwd.UseSystemPasswordChar = !chkShowPwd.Checked;
			};
			poll = new System.Windows.Forms.Timer();
			poll.Interval = 2000;
			poll.Tick += delegate
			{
				PollStatus();
			};
			banner = new System.Windows.Forms.Timer();
			banner.Interval = 800;
			banner.Tick += delegate
			{
				try
				{
					string path = Path.Combine(Program.LocalDir, "banner.txt");
					if (File.Exists(path))
					{
						string text = File.ReadAllText(path, Encoding.UTF8);
						File.Delete(path);
						SetStatus(text, Color.FromArgb(185, 28, 28));
					}
				}
				catch
				{
				}
			};
			banner.Start();
			autoScan = new System.Windows.Forms.Timer();
			autoScan.Interval = 20000;
			autoScan.Tick += delegate
			{
				if (!connected && !connecting && !scanning && lastKey != "pending" && string.IsNullOrEmpty(tbServer.Text.Trim()))
				{
					DoScan(true);
				}
			};
			autoScan.Start();
			base.AcceptButton = btnConnect;
			UpdateMainButton();
			ResumeLayout();
		}
	}
	internal static class LocalLock
	{
		private const string Prefix = "NetGateLock";

		private static string StateFile
		{
			get
			{
				return Path.Combine(Program.LocalDir, "locked.flag");
			}
		}

		public static bool IsActive()
		{
			try
			{
				return File.Exists(StateFile);
			}
			catch
			{
				return false;
			}
		}

		public static bool Apply(out string[] messages)
		{
			List<string> list = new List<string>();
			bool flag = true;
			try
			{
				Remove();
				string selfPath = Program.SelfPath;
				ConfigPorts.Get("server");
				ConfigPorts.Get("port");
				flag &= Netsh("advfirewall firewall add rule name=NetGateLock_App dir=out action=allow program=\"" + selfPath + "\" profile=any");
				flag &= Netsh("advfirewall firewall add rule name=NetGateLock_Loop dir=out action=allow remoteip=127.0.0.1 profile=any");
				flag &= Netsh("advfirewall firewall add rule name=NetGateLock_BlockTcp dir=out action=block protocol=TCP remoteip=0.0.0.0/0 profile=domain,private");
				flag &= Netsh("advfirewall firewall add rule name=NetGateLock_BlockUdp dir=out action=block protocol=UDP remoteip=0.0.0.0/0 profile=domain,private");
				flag &= Netsh("advfirewall set privateprofile firewallpolicy allowinbound,blockoutbound");
				flag &= Netsh("advfirewall set domainprofile firewallpolicy allowinbound,blockoutbound");
				if (flag)
				{
					try
					{
						File.WriteAllText(StateFile, "1");
					}
					catch
					{
					}
				}
				list.Add(flag ? ("本机网络已锁定：只有 " + Path.GetFileName(selfPath) + " 能上网") : "锁定失败（需要管理员权限）");
			}
			catch (Exception ex)
			{
				flag = false;
				list.Add("锁定失败：" + ex.Message);
			}
			messages = list.ToArray();
			return flag;
		}

		public static void Remove()
		{
			try
			{
				if (File.Exists(StateFile))
				{
					File.Delete(StateFile);
				}
			}
			catch
			{
			}
			string[] array = new string[4] { "_App", "_Loop", "_BlockTcp", "_BlockUdp" };
			foreach (string text in array)
			{
				Netsh("advfirewall firewall delete rule name=NetGateLock" + text);
			}
			Netsh("advfirewall set privateprofile firewallpolicy allowinbound,allowoutbound");
			Netsh("advfirewall set domainprofile firewallpolicy allowinbound,allowoutbound");
		}

		private static bool Netsh(string args)
		{
			try
			{
				ProcessStartInfo processStartInfo = new ProcessStartInfo("netsh", args);
				processStartInfo.UseShellExecute = false;
				processStartInfo.CreateNoWindow = true;
				processStartInfo.RedirectStandardOutput = true;
				processStartInfo.RedirectStandardError = true;
				ProcessStartInfo startInfo = processStartInfo;
				using (Process process = Process.Start(startInfo))
				{
					process.WaitForExit(8000);
					return process.ExitCode == 0;
				}
			}
			catch
			{
				return false;
			}
		}
	}
	internal static class ConfigPorts
	{
		public static string Get(string key)
		{
			try
			{
				ClientConfig clientConfig = ClientConfig.Load();
				if (key == "server")
				{
					return clientConfig.Server;
				}
				if (key == "port")
				{
					return clientConfig.Port.ToString();
				}
			}
			catch
			{
			}
			return "";
		}
	}
	internal class ClientConfig
	{
		public string Server = "";

		public int Port = 8899;

		public string Password = "";

		public bool Remember = true;

		private static string FilePath
		{
			get
			{
				return Path.Combine(Program.LocalDir, "client.ini");
			}
		}

		public static ClientConfig Load()
		{
			ClientConfig clientConfig = new ClientConfig();
			try
			{
				if (!File.Exists(FilePath))
				{
					return clientConfig;
				}
				string[] array = File.ReadAllLines(FilePath, Encoding.UTF8);
				foreach (string text in array)
				{
					int num = text.IndexOf('=');
					if (num > 0)
					{
						string text2 = text.Substring(0, num);
						string text3 = text.Substring(num + 1);
						switch (text2)
						{
						case "server":
							clientConfig.Server = text3;
							break;
						case "port":
							clientConfig.Port = (int)Util.AsLong(text3);
							break;
						case "password":
							clientConfig.Password = Uri.UnescapeDataString(text3);
							break;
						case "remember":
							clientConfig.Remember = text3 == "1";
							break;
						}
					}
				}
				if (clientConfig.Port <= 0)
				{
					clientConfig.Port = 8899;
					return clientConfig;
				}
				return clientConfig;
			}
			catch
			{
				return clientConfig;
			}
		}

		public void Save()
		{
			try
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendLine("server=" + Server);
				stringBuilder.AppendLine("port=" + Port);
				stringBuilder.AppendLine("password=" + Uri.EscapeDataString(Password ?? ""));
				stringBuilder.AppendLine("remember=" + (Remember ? "1" : "0"));
				File.WriteAllText(FilePath, stringBuilder.ToString(), new UTF8Encoding(false));
			}
			catch
			{
			}
		}
	}
	internal static class SystemProxy
	{
		private const string Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

		private const string BypassList = "<local>;localhost;127.*;10.*;169.254.*;192.168.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;*.local";

		private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;

		private const int INTERNET_OPTION_REFRESH = 37;

		private static string BackupFile
		{
			get
			{
				return Path.Combine(Program.LocalDir, "proxy-backup.ini");
			}
		}

		[DllImport("wininet.dll", SetLastError = true)]
		private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

		public static void Apply(string ip, int port)
		{
			try
			{
				if (!File.Exists(BackupFile))
				{
					SaveBackup();
				}
				using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", true))
				{
					if (registryKey == null)
					{
						return;
					}
					registryKey.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
					registryKey.SetValue("ProxyServer", ip + ":" + port, RegistryValueKind.String);
					registryKey.SetValue("ProxyOverride", "<local>;localhost;127.*;10.*;169.254.*;192.168.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;*.local", RegistryValueKind.String);
					registryKey.DeleteValue("AutoConfigURL", false);
				}
				Flush();
			}
			catch (Exception ex)
			{
				Program.Dbg("proxy apply: " + ex.Message);
			}
		}

		// 上次异常退出可能把系统代理留在 127.0.0.1:端口，启动时先恢复，避免“上不了网”。
		public static void RecoverIfStale()
		{
			try
			{
				if (!File.Exists(BackupFile))
				{
					return;
				}
				bool pointsToUs = false;
				using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", false))
				{
					if (registryKey != null)
					{
						object value = registryKey.GetValue("ProxyEnable");
						string text = registryKey.GetValue("ProxyServer") as string;
						pointsToUs = value != null && Convert.ToInt32(value) != 0 && !string.IsNullOrEmpty(text) && (text.StartsWith("127.0.0.1:", StringComparison.Ordinal) || text.StartsWith("localhost:", StringComparison.OrdinalIgnoreCase));
					}
				}
				if (pointsToUs)
				{
					Program.Dbg("recover stale proxy");
					Restore();
				}
				else
				{
					// 代理已被用户手动改过，旧备份不再适用，删掉以免下次连接时覆盖当前设置
					File.Delete(BackupFile);
				}
			}
			catch (Exception ex)
			{
				Program.Dbg("proxy recover: " + ex.Message);
			}
		}

		public static void Restore()
		{
			try
			{
				if (!File.Exists(BackupFile))
				{
					return;
				}
				string[] array = File.ReadAllLines(BackupFile, Encoding.UTF8);
				using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", true))
				{
					if (registryKey == null)
					{
						return;
					}
					string[] array2 = array;
					foreach (string text in array2)
					{
						int num = text.IndexOf('=');
						if (num > 0)
						{
							string text2 = text.Substring(0, num);
							string text3 = text.Substring(num + 1);
							if (text2 == "ProxyEnable")
							{
								registryKey.SetValue(text2, (int)Util.AsLong(text3), RegistryValueKind.DWord);
							}
							else if (text3.Length == 0)
							{
								registryKey.DeleteValue(text2, false);
							}
							else
							{
								registryKey.SetValue(text2, text3, RegistryValueKind.String);
							}
						}
					}
				}
				File.Delete(BackupFile);
				Flush();
			}
			catch (Exception ex)
			{
				Program.Dbg("proxy restore: " + ex.Message);
			}
		}

		private static void SaveBackup()
		{
			StringBuilder stringBuilder = new StringBuilder();
			using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", false))
			{
				if (registryKey == null)
				{
					return;
				}
				object value = registryKey.GetValue("ProxyEnable");
				stringBuilder.AppendLine("ProxyEnable=" + ((value == null) ? "0" : value.ToString()));
				stringBuilder.AppendLine("ProxyServer=" + ((registryKey.GetValue("ProxyServer") as string) ?? ""));
				stringBuilder.AppendLine("ProxyOverride=" + ((registryKey.GetValue("ProxyOverride") as string) ?? ""));
				stringBuilder.AppendLine("AutoConfigURL=" + ((registryKey.GetValue("AutoConfigURL") as string) ?? ""));
			}
			File.WriteAllText(BackupFile, stringBuilder.ToString(), new UTF8Encoding(false));
		}

		private static void Flush()
		{
			try
			{
				InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
				InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
			}
			catch
			{
			}
		}
	}
	public sealed class TransferEntry
	{
		public string Name;

		public long Size;
	}
	public sealed class TransferOffer
	{
		public string SenderId = "";

		public string SenderName = "";

		public string SenderIp = "";

		public long Total;

		public List<TransferEntry> Files = new List<TransferEntry>();
	}
	public sealed class ChatMessage
	{
		public string FromId = "";

		public string FromName = "";

		public string FromHost = "";

		public string FromIp = "";

		public string Text = "";

		public DateTime At = DateTime.Now;
	}
	public sealed class TransferPeer
	{
		public string Id = "";

		public string Name = "";

		public string User = "";

		public string Ip = "";

		public int Port;

		public string Display
		{
			get
			{
				if (!string.IsNullOrEmpty(Name))
				{
					return Name;
				}
				return Ip;
			}
		}
	}
	public sealed class FileTransferService
	{
		public const int TcpPort = 8896;

		public const int UdpPort = 8895;

		// 局域网发现使用的 UDP 端口（都在防火墙放行的 8895-8905 范围内）。
		// 多个实例时对方可能落在顺延端口上，所以扫描端逐个端口都发一遍。
		public static readonly int[] ScanPorts = new int[5] { 8895, 8896, 8897, 8898, 8899 };

		// 每轮广播的重发次数与间隔
		private const int BroadcastRounds = 8;

		// Windows: SIO_UDP_CONNRESET，禁用 ICMP 端口不可达导致的 10054 错误
		// （单播扫描会给大量不存在的地址发包，不禁用的话 Receive 会被 ICMP 打断）
		private const int UdpResetControlCode = unchecked((int)0x9800000C);

		private static FileTransferService current;

		public readonly string LocalId = Guid.NewGuid().ToString("N").Substring(0, 10);

		public string LocalName;

		public string ReceiveDir;

		public static Control UiOwner;

		public Func<TransferOffer, string> AutoAccept;

		public Action<string> OnLog;

		public Action<long, long, string> OnProgress;

		// 收到局域网聊天消息（窗口和主界面都可以订阅）
		public static event Action<ChatMessage> ChatArrived;

		// ---- 控制端下发的禁言名单（群聊实例 ID）----
		// 控制端把某台设备设为禁言后，所有客户端都会收到这份名单：
		// 被禁言的设备发不出消息，别的客户端也会忽略它发来的消息。
		private static readonly HashSet<string> mutedCids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		public static void SetMutedCids(string csv)
		{
			List<string> list = new List<string>();
			if (!string.IsNullOrEmpty(csv))
			{
				string[] array = csv.Split(',');
				foreach (string text in array)
				{
					string text2 = text.Trim();
					if (text2.Length > 0 && !list.Contains(text2))
					{
						list.Add(text2);
					}
				}
			}
			lock (mutedCids)
			{
				mutedCids.Clear();
				foreach (string item in list)
				{
					mutedCids.Add(item);
				}
			}
		}

		public static bool IsMutedId(string id)
		{
			if (string.IsNullOrEmpty(id))
			{
				return false;
			}
			lock (mutedCids)
			{
				return mutedCids.Contains(id.Trim());
			}
		}

		// 本机是否被控制端禁言
		public static bool IsSelfMuted()
		{
			try
			{
				return IsMutedId(Current.LocalId);
			}
			catch
			{
				return false;
			}
		}

		// ---- 控制端单方面屏蔽：按 IP 过滤，不需要客户端配合 ----
		// 控制端把某台设备禁言后，只在自己这边丢掉它发的群聊消息（不显示、不写记录）。
		private static readonly HashSet<string> mutedIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		public static void SetMutedIps(string csv)
		{
			List<string> list = new List<string>();
			if (!string.IsNullOrEmpty(csv))
			{
				string[] array = csv.Split(',');
				foreach (string text in array)
				{
					string text2 = text.Trim();
					if (text2.Length > 0 && !list.Contains(text2))
					{
						list.Add(text2);
					}
				}
			}
			lock (mutedIps)
			{
				mutedIps.Clear();
				foreach (string item in list)
				{
					mutedIps.Add(item);
				}
			}
		}

		public static bool IsMutedIp(string ip)
		{
			if (string.IsNullOrEmpty(ip))
			{
				return false;
			}
			lock (mutedIps)
			{
				return mutedIps.Contains(ip.Trim());
			}
		}

		private TcpListener tcp;

		private TcpClient pendingClient;

		private UdpClient udp;

		private Thread acceptThread;

		private Thread udpThread;

		private volatile bool running;

		private int tcpPort;

		private int udpPort;

		private int incomingBusy;

		private readonly object logLock = new object();

		private static int lastPeerCount = -1;

		private static DateTime lastStartFailLog = DateTime.MinValue;

		private static DateTime lastSweepUtc = DateTime.MinValue;

		private static string lastPeerCacheText;

		private static readonly object chatLogLock = new object();

		public static FileTransferService Current
		{
			get
			{
				if (current == null)
				{
					current = new FileTransferService();
				}
				return current;
			}
		}

		public int TcpListenPort
		{
			get
			{
				return tcpPort;
			}
		}

		public int UdpListenPort
		{
			get
			{
				return udpPort;
			}
		}

		public bool Running
		{
			get
			{
				return running;
			}
		}

		public static void EnsureStarted()
		{
			try
			{
				FileTransferService fileTransferService = Current;
				if (fileTransferService.running)
				{
					return;
				}
				fileTransferService.Start();
			}
			catch (Exception ex)
			{
				try
				{
					if (DateTime.UtcNow - lastStartFailLog > TimeSpan.FromSeconds(30))
					{
						lastStartFailLog = DateTime.UtcNow;
						Current.Log("文件传输启动失败：" + ex.Message);
					}
				}
				catch
				{
				}
			}
		}

		public static void StopAll()
		{
			FileTransferService fileTransferService = current;
			if (fileTransferService != null)
			{
				fileTransferService.Stop();
			}
		}

		public FileTransferService()
		{
			TransferConfigData transferConfigData = TransferConfig.Load();
			LocalName = transferConfigData.Name;
			ReceiveDir = transferConfigData.SaveDir;
			tcpPort = 8896;
			udpPort = 8895;
		}

		public void Start()
		{
			if (running)
			{
				return;
			}
			Exception ex = null;
			for (int i = 0; i < 10; i++)
			{
				try
				{
					tcp = new TcpListener(IPAddress.Any, 8896 + i);
					// 不要设 ExclusiveAddressUse=false：那等于打开 SO_REUSEADDR，
					// 同机两个实例会同时绑到 8896，对方连到的可能是另一个进程。
					// 绑不上就顺延到 8897、8898……
					tcp.Start(50);
					tcpPort = 8896 + i;
					ex = null;
				}
				catch (Exception ex2)
				{
					ex = ex2;
					tcp = null;
					continue;
				}
				break;
			}
			if (tcp == null)
			{
				throw ex ?? new Exception("文件传输端口被占用");
			}
			Exception udpError = null;
			for (int j = 0; j < ScanPorts.Length; j++)
			{
				try
				{
					UdpClient udpClient = new UdpClient();
					udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, ScanPorts[j]));
					udp = udpClient;
					udpPort = ScanPorts[j];
					udpError = null;
				}
				catch (Exception ex3)
				{
					udpError = ex3;
					udp = null;
					continue;
				}
				break;
			}
			running = true;
			acceptThread = new Thread(AcceptLoop);
			acceptThread.IsBackground = true;
			acceptThread.Start();
			if (udp != null)
			{
				udpThread = new Thread(UdpLoop);
				udpThread.IsBackground = true;
				udpThread.Start();
			}
			Log("文件传输已启动：TCP " + tcpPort + " / UDP " + ((udp != null) ? udpPort.ToString() : "未监听"));
			if (udp == null)
			{
				Log("警告：UDP 8895-8899 全部绑定失败，其它电脑扫描不到本机（" + ((udpError == null) ? "原因未知" : udpError.Message) + "）");
			}
		}

		public void Stop()
		{
			running = false;
			try
			{
				if (tcp != null)
				{
					tcp.Stop();
				}
			}
			catch
			{
			}
			try
			{
				if (udp != null)
				{
					udp.Close();
				}
			}
			catch
			{
			}
			try
			{
				if (pendingClient != null)
				{
					pendingClient.Close();
				}
			}
			catch
			{
			}
			tcp = null;
			udp = null;
		}

		/// <summary>
		/// 局域网发现。先用广播（255.255.255.255 + 每块网卡的定向广播）连发多轮，
		/// 广播拿不到结果时再逐个地址单播（很多交换机 / 无线 AP 会丢广播）。
		/// 扫描端会同时打 8895-8899 五个端口，因为同机多开时监听端口会顺延。
		/// </summary>
		public List<TransferPeer> Discover(int timeoutMs)
		{
			if (timeoutMs <= 0)
			{
				timeoutMs = 2500;
			}
			List<TransferPeer> list = new List<TransferPeer>();
			HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			UdpClient socket = null;
			try
			{
				socket = new UdpClient();
				try
				{
					socket.Client.IOControl(UdpResetControlCode, new byte[4], null);
				}
				catch
				{
				}
				socket.EnableBroadcast = true;
				socket.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
				socket.Client.ReceiveTimeout = 100;
				try
				{
					socket.Client.ReceiveBufferSize = 262144;
				}
				catch
				{
				}
				byte[] request = Encoding.UTF8.GetBytes("NETGATE_DISCOVER_V1|" + LocalId);
				List<IPAddress> broadcastTargets = BuildBroadcastTargets();
				DateTime start = DateTime.UtcNow;
				DateTime deadline = start.AddMilliseconds(timeoutMs);
				DateTime broadcastEnd = start.AddMilliseconds(Math.Min(timeoutMs, 1200));
				DateTime nextSend = start;
				int rounds = 0;
				while (DateTime.UtcNow < broadcastEnd && rounds < BroadcastRounds)
				{
					if (DateTime.UtcNow >= nextSend)
					{
						foreach (IPAddress target in broadcastTargets)
						{
							SendDiscover(socket, request, target);
						}
						rounds++;
						nextSend = DateTime.UtcNow.AddMilliseconds(300);
					}
					ReceivePeers(socket, list, seen, DateTime.UtcNow.AddMilliseconds(120));
				}
				if (list.Count == 0 && (DateTime.UtcNow - lastSweepUtc).TotalSeconds >= 60.0)
				{
					// 广播没结果：换成逐个地址单播（含上次见过的地址），绕过广播被拦的情况。
					// 单播扫描比较吵，所以最多每分钟做一次。
					lastSweepUtc = DateTime.UtcNow;
					List<IPAddress> sweepTargets = BuildUnicastSweepTargets();
					foreach (TransferPeer cached in LoadPeerCache())
					{
						IPAddress cachedAddress;
						if (!string.IsNullOrEmpty(cached.Ip) && IPAddress.TryParse(cached.Ip, out cachedAddress) && !sweepTargets.Contains(cachedAddress))
						{
							sweepTargets.Insert(0, cachedAddress);
						}
					}
					if (sweepTargets.Count > 0)
					{
						Log("广播没有应答，改为逐个地址单播探测 " + sweepTargets.Count + " 个地址");
					}
					// 一次性把探测包全发出去，剩下的时间专心收应答；
					// 不再分批 sleep，否则大网段扫不完。
					int index = 0;
					while (index < sweepTargets.Count)
					{
						int batchEnd = Math.Min(sweepTargets.Count, index + 32);
						while (index < batchEnd)
						{
							SendDiscover(socket, request, sweepTargets[index]);
							index++;
						}
						if (DateTime.UtcNow >= deadline)
						{
							break;
						}
					}
				}
				while (DateTime.UtcNow < deadline)
				{
					ReceivePeers(socket, list, seen, deadline);
				}
				if (list.Count > 0)
				{
					SavePeerCache(list);
				}
				if (list.Count != lastPeerCount)
				{
					lastPeerCount = list.Count;
					Log("局域网扫描完成：发现 " + list.Count + " 台 NetGate 电脑（广播目标 " + broadcastTargets.Count + " 个）");
				}
			}
			catch (Exception ex)
			{
				Log("扫描出错：" + ex.Message);
			}
			finally
			{
				try
				{
					if (socket != null)
					{
						socket.Close();
					}
				}
				catch
				{
				}
			}
			return list;
		}

		private static void SendDiscover(UdpClient socket, byte[] request, IPAddress target)
		{
			for (int i = 0; i < ScanPorts.Length; i++)
			{
				try
				{
					socket.Send(request, request.Length, new IPEndPoint(target, ScanPorts[i]));
				}
				catch
				{
				}
			}
		}

		private bool ReceivePeers(UdpClient socket, List<TransferPeer> list, HashSet<string> seen, DateTime until)
		{
			bool flag = false;
			while (DateTime.UtcNow < until)
			{
				IPEndPoint remoteEP = null;
				byte[] array;
				try
				{
					array = socket.Receive(ref remoteEP);
				}
				catch (SocketException)
				{
					// 100ms 收不到就返回，让上层继续发下一轮
					return flag;
				}
				catch (ObjectDisposedException)
				{
					return flag;
				}
				catch
				{
					return flag;
				}
				TransferPeer peer = ParseReply(array, remoteEP);
				if (peer != null)
				{
					MergePeer(list, seen, peer);
					flag = true;
				}
			}
			return flag;
		}

		private TransferPeer ParseReply(byte[] data, IPEndPoint remote)
		{
			try
			{
				if (data == null || data.Length == 0)
				{
					return null;
				}
				string[] array = Encoding.UTF8.GetString(data).Trim().Split('|');
				if (array.Length < 4 || array[0].Trim() != "NETGATE_HERE_V1")
				{
					return null;
				}
				string text = array[1].Trim();
				int result;
				if (text.Length == 0 || text == LocalId || !int.TryParse(array[3].Trim(), out result) || result <= 0 || result > 65535)
				{
					return null;
				}
				TransferPeer transferPeer = new TransferPeer();
				transferPeer.Id = text;
				transferPeer.Port = result;
				transferPeer.User = ((array.Length > 4) ? Decode(array[4]).Trim() : "");
				transferPeer.Ip = ((remote == null) ? "" : remote.Address.ToString());
				transferPeer.Name = Decode(array[2]).Trim();
				if (transferPeer.Name.Length == 0)
				{
					// 名字为空不能丢：用 IP 代替，否则对方永远不显示
					transferPeer.Name = ((transferPeer.Ip.Length > 0) ? transferPeer.Ip : text);
				}
				return transferPeer;
			}
			catch
			{
				return null;
			}
		}

		private static void MergePeer(List<TransferPeer> list, HashSet<string> seen, TransferPeer peer)
		{
			if (!seen.Contains(peer.Id))
			{
				seen.Add(peer.Id);
				list.Add(peer);
				return;
			}
			for (int i = 0; i < list.Count; i++)
			{
				TransferPeer transferPeer = list[i];
				if (transferPeer.Id != peer.Id)
				{
					continue;
				}
				bool flag = transferPeer.Ip.StartsWith("127.") || transferPeer.Ip.StartsWith("169.254.");
				bool flag2 = peer.Ip.Length > 0 && !peer.Ip.StartsWith("127.") && !peer.Ip.StartsWith("169.254.");
				if (flag && flag2)
				{
					transferPeer.Ip = peer.Ip;
					transferPeer.Port = peer.Port;
					transferPeer.Name = peer.Name;
				}
				return;
			}
		}

		/// <summary>
		/// 手动按 IP 探测：给「广播扫不到、但知道对方 IP」的情况用。
		/// host 可以是 192.168.1.5 或 192.168.1.5:8896。
		/// </summary>
		public TransferPeer ProbePeer(string host, int timeoutMs)
		{
			string text = (host ?? "").Trim();
			int num = 0;
			IPAddress address = null;
			int num2 = text.LastIndexOf(':');
			if (num2 > 0)
			{
				int.TryParse(text.Substring(num2 + 1), out num);
				text = text.Substring(0, num2).Trim();
			}
			if (!IPAddress.TryParse(text, out address))
			{
				return null;
			}
			UdpClient socket = null;
			try
			{
				socket = new UdpClient();
				try
				{
					socket.Client.IOControl(UdpResetControlCode, new byte[4], null);
				}
				catch
				{
				}
				socket.EnableBroadcast = true;
				socket.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
				socket.Client.ReceiveTimeout = 100;
				byte[] request = Encoding.UTF8.GetBytes("NETGATE_DISCOVER_V1|" + LocalId);
				DateTime dateTime = DateTime.UtcNow.AddMilliseconds(Math.Max(300, timeoutMs));
				DateTime nextSend = DateTime.UtcNow;
				while (DateTime.UtcNow < dateTime)
				{
					if (DateTime.UtcNow >= nextSend)
					{
						if (num > 0)
						{
							try
							{
								socket.Send(request, request.Length, new IPEndPoint(address, num));
							}
							catch
							{
							}
						}
						else
						{
							SendDiscover(socket, request, address);
						}
						nextSend = DateTime.UtcNow.AddMilliseconds(300);
					}
					try
					{
						IPEndPoint remoteEP = null;
						byte[] array = socket.Receive(ref remoteEP);
						TransferPeer transferPeer = ParseReply(array, remoteEP);
						if (transferPeer != null)
						{
							return transferPeer;
						}
					}
					catch (SocketException)
					{
					}
					catch
					{
					}
				}
				return null;
			}
			catch
			{
				return null;
			}
			finally
			{
				try
				{
					if (socket != null)
					{
						socket.Close();
					}
				}
				catch
				{
				}
			}
		}

		private static string PeerCachePath
		{
			get
			{
				return Path.Combine(Program.DataDir, "peers.ini");
			}
		}

		// 记住上次扫到的电脑，下次广播被拦时还能按 IP 单播找回
		private static void SavePeerCache(List<TransferPeer> peers)
		{
			try
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendLine("# NetGate 最近一次扫描到的电脑（自动生成，可删除）");
				int num = 0;
				foreach (TransferPeer peer in peers)
				{
					if (num++ >= 30 || string.IsNullOrEmpty(peer.Ip))
					{
						break;
					}
					stringBuilder.AppendLine(peer.Id + "|" + peer.Ip + "|" + peer.Port + "|" + Uri.EscapeDataString(peer.Name ?? ""));
				}
				Directory.CreateDirectory(Program.DataDir);
				string text = stringBuilder.ToString();
				if (text != lastPeerCacheText)
				{
					lastPeerCacheText = text;
					File.WriteAllText(PeerCachePath, text, new UTF8Encoding(false));
				}
			}
			catch
			{
			}
		}

		private static List<TransferPeer> LoadPeerCache()
		{
			List<TransferPeer> list = new List<TransferPeer>();
			try
			{
				if (!File.Exists(PeerCachePath))
				{
					return list;
				}
				foreach (string text in File.ReadAllLines(PeerCachePath, Encoding.UTF8))
				{
					string text2 = (text ?? "").Trim();
					if (text2.Length == 0 || text2.StartsWith("#"))
					{
						continue;
					}
					string[] array = text2.Split('|');
					if (array.Length < 3)
					{
						continue;
					}
					TransferPeer transferPeer = new TransferPeer();
					transferPeer.Id = array[0];
					transferPeer.Ip = array[1];
					int result;
					transferPeer.Port = (int.TryParse(array[2], out result) ? result : 8896);
					transferPeer.Name = ((array.Length > 3) ? Uri.UnescapeDataString(array[3]) : transferPeer.Ip);
					list.Add(transferPeer);
				}
			}
			catch
			{
			}
			return list;
		}

		// 收集本机所有网卡的定向广播地址（多网卡时每个网段都要发）
		private static List<IPAddress> BuildBroadcastTargets()
		{
			List<IPAddress> list = new List<IPAddress>();
			list.Add(IPAddress.Broadcast);
			try
			{
				foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
				{
					if (networkInterface.OperationalStatus != OperationalStatus.Up)
					{
						continue;
					}
					if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
					{
						continue;
					}
					foreach (UnicastIPAddressInformation unicastAddress in networkInterface.GetIPProperties().UnicastAddresses)
					{
						if (unicastAddress.Address.AddressFamily != AddressFamily.InterNetwork)
						{
							continue;
						}
						string text = unicastAddress.Address.ToString();
						if (text.StartsWith("127.") || text.StartsWith("169.254."))
						{
							continue;
						}
						IPAddress item = GetBroadcastAddress(unicastAddress);
						if (item != null && !list.Contains(item))
						{
							list.Add(item);
						}
					}
				}
			}
			catch
			{
			}
			if (!list.Contains(IPAddress.Loopback))
			{
				list.Add(IPAddress.Loopback);
			}
			return list;
		}

		// 按真实子网掩码算定向广播地址（以前写死 /24，掩码不是 /24 时广播地址是错的）
		private static IPAddress GetBroadcastAddress(UnicastIPAddressInformation info)
		{
			try
			{
				byte[] addressBytes = info.Address.GetAddressBytes();
				if (addressBytes.Length != 4)
				{
					return null;
				}
				byte[] array = null;
				try
				{
					IPAddress iPv4Mask = info.IPv4Mask;
					if (iPv4Mask != null)
					{
						array = iPv4Mask.GetAddressBytes();
					}
				}
				catch
				{
				}
				if (array == null || array.Length != 4)
				{
					array = new byte[4];
					array[0] = byte.MaxValue;
					array[1] = byte.MaxValue;
					array[2] = byte.MaxValue;
				}
				byte[] array2 = new byte[4];
				for (int i = 0; i < 4; i++)
				{
					array2[i] = (byte)(addressBytes[i] | (~array[i] & 0xFF));
				}
				return new IPAddress(array2);
			}
			catch
			{
				return null;
			}
		}

		// 逐个地址单播用：每块网卡的子网内所有主机地址（网段大于 /24 时只取本机所在的 /24，上限 1024 个）
		private static List<IPAddress> BuildUnicastSweepTargets()
		{
			List<IPAddress> list = new List<IPAddress>();
			HashSet<uint> hashSet = new HashSet<uint>();
			try
			{
				foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
				{
					if (networkInterface.OperationalStatus != OperationalStatus.Up)
					{
						continue;
					}
					if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
					{
						continue;
					}
					foreach (UnicastIPAddressInformation unicastAddress in networkInterface.GetIPProperties().UnicastAddresses)
					{
						if (unicastAddress.Address.AddressFamily != AddressFamily.InterNetwork)
						{
							continue;
						}
						string text = unicastAddress.Address.ToString();
						if (text.StartsWith("127.") || text.StartsWith("169.254."))
						{
							continue;
						}
						byte[] addressBytes = unicastAddress.Address.GetAddressBytes();
						uint ip = ToUInt32(addressBytes);
						uint num = 4294967040u;
						try
						{
							IPAddress iPv4Mask = unicastAddress.IPv4Mask;
							if (iPv4Mask != null)
							{
								num = ToUInt32(iPv4Mask.GetAddressBytes());
							}
						}
						catch
						{
						}
						uint network = ip & num;
						uint num2 = ~num;
						if (num2 > 254)
						{
							network = ip & 4294967040u;
							num2 = 255;
						}
						if (num2 < 2)
						{
							continue;
						}
						uint num3 = network + num2;
						for (uint num4 = network + 1; num4 < num3 && list.Count < 1024; num4++)
						{
							if (num4 != ip && hashSet.Add(num4))
							{
								list.Add(FromUInt32(num4));
							}
						}
					}
				}
			}
			catch
			{
			}
			// 同机多开时（控制端 + 用户端）也能被扫到
			if (!list.Contains(IPAddress.Loopback))
			{
				list.Add(IPAddress.Loopback);
			}
			return list;
		}

		private static uint ToUInt32(byte[] bytes)
		{
			return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
		}

		private static IPAddress FromUInt32(uint value)
		{
			return new IPAddress(new byte[4]
			{
				(byte)(value >> 24),
				(byte)(value >> 16),
				(byte)(value >> 8),
				(byte)value
			});
		}

		private void UdpLoop()
		{
			while (running)
			{
				try
				{
					if (udp == null)
					{
						break;
					}
					IPEndPoint remoteEP = null;
					byte[] array = udp.Receive(ref remoteEP);
					if (array == null || array.Length == 0 || remoteEP == null)
					{
						continue;
					}
					string[] array2 = Encoding.UTF8.GetString(array).Trim().Split('|');
					if (array2.Length >= 2 && array2[0].Trim() == "NETGATE_DISCOVER_V1" && array2[1].Trim() != LocalId)
					{
						string s = "NETGATE_HERE_V1|" + LocalId + "|" + Encode(LocalName) + "|" + tcpPort + "|" + Encode(Environment.UserName) + "|" + Encode(Environment.MachineName);
						byte[] bytes = Encoding.UTF8.GetBytes(s);
						try
						{
							udp.Send(bytes, bytes.Length, remoteEP);
						}
						catch
						{
						}
					}
				}
				catch (ObjectDisposedException)
				{
					break;
				}
				catch
				{
					if (!running)
					{
						break;
					}
					Thread.Sleep(50);
				}
			}
		}

		public string Send(TransferPeer peer, string[] files, Action<long, long, string> progress, out string error)
		{
			error = null;
			if (peer == null)
			{
				error = "没有选择接收方";
				return null;
			}
			if (files == null || files.Length == 0)
			{
				error = "没有选择文件";
				return null;
			}
			List<TransferEntry> list = new List<TransferEntry>();
			List<string> list2 = new List<string>();
			long num = 0L;
			foreach (string fileName in files)
			{
				try
				{
					FileInfo fileInfo = new FileInfo(fileName);
					if (fileInfo.Exists)
					{
						TransferEntry transferEntry = new TransferEntry();
						transferEntry.Name = fileInfo.Name;
						transferEntry.Size = fileInfo.Length;
						list.Add(transferEntry);
						list2.Add(fileInfo.FullName);
						num += fileInfo.Length;
					}
				}
				catch
				{
				}
			}
			if (list.Count == 0)
			{
				error = "文件不存在或无法读取";
				return null;
			}
			TcpClient tcpClient = null;
			try
			{
				tcpClient = new TcpClient();
				tcpClient.NoDelay = true;
				IAsyncResult asyncResult = tcpClient.BeginConnect(peer.Ip, peer.Port, null, null);
				if (!asyncResult.AsyncWaitHandle.WaitOne(5000))
				{
					error = "连接接收方超时";
					return null;
				}
				tcpClient.EndConnect(asyncResult);
				NetworkStream stream = tcpClient.GetStream();
				stream.ReadTimeout = 120000;
				stream.WriteTimeout = 120000;
				WriteLine(stream, "OFFER\t" + LocalId + "\t" + Encode(LocalName) + "\t" + list.Count + "\t" + num);
				foreach (TransferEntry item in list)
				{
					WriteLine(stream, "ENTRY\t" + Encode(item.Name) + "\t" + item.Size);
				}
				string text = ReadLine(stream);
				if (text == null || !text.StartsWith("YES", StringComparison.Ordinal))
				{
					error = ((text != null && text.StartsWith("NO", StringComparison.Ordinal)) ? "对方拒绝了接收" : "对方未响应");
					return null;
				}
				long num2 = 0L;
				byte[] array = new byte[65536];
				for (int j = 0; j < list.Count; j++)
				{
					TransferEntry transferEntry3 = list[j];
					WriteLine(stream, "FILE\t" + Encode(transferEntry3.Name) + "\t" + transferEntry3.Size);
					using (FileStream fileStream = new FileStream(list2[j], FileMode.Open, FileAccess.Read, FileShare.Read))
					{
						long num3 = transferEntry3.Size;
						while (num3 > 0)
						{
							int num4 = fileStream.Read(array, 0, (int)Math.Min(array.Length, num3));
							if (num4 <= 0)
							{
								break;
							}
							stream.Write(array, 0, num4);
							num2 += num4;
							num3 -= num4;
							if (progress != null)
							{
								progress(num2, num, transferEntry3.Name);
							}
							else if (OnProgress != null)
							{
								OnProgress(num2, num, transferEntry3.Name);
							}
						}
						if (num3 > 0)
						{
							throw new IOException("文件在发送过程中被截断：" + transferEntry3.Name);
						}
					}
				}
				WriteLine(stream, "END");
				string text2 = ReadLine(stream);
				if (text2 == null || !text2.StartsWith("OK", StringComparison.Ordinal))
				{
					error = "接收方保存文件失败";
					return null;
				}
				Log("已发送 " + list.Count + " 个文件到 " + peer.Display + "（" + Util.FmtBytes(num) + "）");
				return "OK";
			}
			catch (Exception ex)
			{
				error = ex.Message;
				return null;
			}
			finally
			{
				try
				{
					if (tcpClient != null)
					{
						tcpClient.Close();
					}
				}
				catch
				{
				}
			}
		}

		private void AcceptLoop()
		{
			while (running)
			{
				TcpClient c = null;
				try
				{
					if (tcp == null)
					{
						break;
					}
					c = tcp.AcceptTcpClient();
					pendingClient = c;
					Thread thread = new Thread((ThreadStart)delegate
					{
						HandleClient(c);
					});
					thread.IsBackground = true;
					thread.Start();
				}
				catch
				{
					if (!running)
					{
						break;
					}
					Thread.Sleep(50);
				}
			}
		}

		private void HandleClient(TcpClient c)
		{
			string text = null;
			string text2 = null;
			List<string> list = new List<string>();
			try
			{
				c.NoDelay = true;
				NetworkStream stream = c.GetStream();
				stream.ReadTimeout = 120000;
				stream.WriteTimeout = 120000;
				string text3 = ReadLine(stream);
				if (text3 != null && text3.StartsWith("CHAT\t", StringComparison.Ordinal))
				{
					HandleChatLine(stream, c, text3);
					return;
				}
				if (text3 != null && text3.StartsWith("HIST\t", StringComparison.Ordinal))
				{
					HandleHistRequest(stream, text3);
					return;
				}
				if (text3 == null || !text3.StartsWith("OFFER\t", StringComparison.Ordinal))
				{
					return;
				}
				string[] array = text3.Split('\t');
				int result;
				long result2;
				if (array.Length < 5 || !int.TryParse(array[3], out result) || result <= 0 || result > 10000 || !long.TryParse(array[4], out result2) || result2 < 0)
				{
					return;
				}
				TransferOffer transferOffer = new TransferOffer();
				transferOffer.SenderId = array[1];
				transferOffer.SenderName = Decode(array[2]);
				transferOffer.Total = result2;
				try
				{
					IPEndPoint iPEndPoint = c.Client.RemoteEndPoint as IPEndPoint;
					if (iPEndPoint != null)
					{
						transferOffer.SenderIp = iPEndPoint.Address.ToString();
					}
				}
				catch
				{
				}
				for (int i = 0; i < result; i++)
				{
					string text4 = ReadLine(stream);
					if (text4 == null || !text4.StartsWith("ENTRY\t", StringComparison.Ordinal))
					{
						return;
					}
					string[] array2 = text4.Split('\t');
					long result3;
					if (array2.Length < 3 || !long.TryParse(array2[2], out result3) || result3 < 0)
					{
						return;
					}
					TransferEntry transferEntry = new TransferEntry();
					transferEntry.Name = SafeName(Decode(array2[1]));
					transferEntry.Size = result3;
					transferOffer.Files.Add(transferEntry);
				}
				if (Interlocked.CompareExchange(ref incomingBusy, 1, 0) != 0)
				{
					Log("拒绝 " + transferOffer.SenderName + "：本机正在接收另一个文件");
					WriteLine(stream, "NO\t" + Encode("本机正在接收另一个文件"));
					return;
				}
				try
				{
					text = AskAccept(transferOffer);
					if (string.IsNullOrEmpty(text))
					{
						Interlocked.Exchange(ref incomingBusy, 0);
						WriteLine(stream, "NO\t" + Encode("接收方取消"));
						Log("已拒绝来自 " + transferOffer.SenderName + " 的文件");
						return;
					}
					Directory.CreateDirectory(text);
					WriteLine(stream, "YES");
					byte[] array3 = new byte[65536];
					long num = 0L;
					for (int j = 0; j < transferOffer.Files.Count; j++)
					{
						string text5 = ReadLine(stream);
						if (text5 == null || !text5.StartsWith("FILE\t", StringComparison.Ordinal))
						{
							throw new IOException("传输协议错误");
						}
						string[] array4 = text5.Split('\t');
						if (array4.Length < 3)
						{
							throw new IOException("传输协议错误");
						}
						string text6 = SafeName(Decode(array4[1]));
						long result4;
						if (!long.TryParse(array4[2], out result4) || result4 < 0)
						{
							throw new IOException("文件长度错误");
						}
						string text7 = UniquePath(text, text6);
						text2 = text7 + ".part";
						using (FileStream fileStream = new FileStream(text2, FileMode.Create, FileAccess.Write, FileShare.None))
						{
							long num2 = result4;
							while (num2 > 0)
							{
								int num3 = stream.Read(array3, 0, (int)Math.Min(array3.Length, num2));
								if (num3 <= 0)
								{
									throw new IOException("连接中断");
								}
								fileStream.Write(array3, 0, num3);
								num2 -= num3;
								num += num3;
								if (OnProgress != null)
								{
									OnProgress(num, result2, text6);
								}
							}
						}
						File.Move(text2, text7);
						text2 = null;
						list.Add(text7);
					}
					string text8 = ReadLine(stream);
					if (text8 == null || !text8.StartsWith("END", StringComparison.Ordinal))
					{
						throw new IOException("传输未完成");
					}
					Interlocked.Exchange(ref incomingBusy, 0);
					WriteLine(stream, "OK");
					Log("已接收来自 " + transferOffer.SenderName + " 的 " + list.Count + " 个文件（" + Util.FmtBytes(result2) + "）到 " + text);
					NotifyReceived(transferOffer, text, list.Count);
				}
				finally
				{
					Interlocked.Exchange(ref incomingBusy, 0);
				}
			}
			catch (Exception ex)
			{
				Log("接收失败：" + ex.Message);
				try
				{
					if (text2 != null && File.Exists(text2))
					{
						File.Delete(text2);
					}
				}
				catch
				{
				}
			}
			finally
			{
				try
				{
					c.Close();
				}
				catch
				{
				}
				if (pendingClient == c)
				{
					pendingClient = null;
				}
			}
		}

		private string AskAccept(TransferOffer offer)
		{
			if (AutoAccept != null)
			{
				string text = AutoAccept(offer);
				if (!string.IsNullOrEmpty(text))
				{
					ReceiveDir = text;
					SaveConfig();
				}
				return text;
			}
			Control owner = UiOwner;
			if (owner == null || owner.IsDisposed || !owner.IsHandleCreated)
			{
				return null;
			}
			try
			{
				return (string)owner.Invoke((Func<string>)delegate
				{
					using (IncomingDialog incomingDialog = new IncomingDialog(offer, ReceiveDir))
					{
						if (incomingDialog.ShowDialog(owner) != DialogResult.OK)
						{
							return null;
						}
						ReceiveDir = incomingDialog.SaveDir;
						SaveConfig();
						return incomingDialog.SaveDir;
					}
				});
			}
			catch
			{
				return null;
			}
		}

		private void NotifyReceived(TransferOffer offer, string dir, int files)
		{
			if (AutoAccept != null)
			{
				return;
			}
			Control owner = UiOwner;
			if (owner == null || owner.IsDisposed)
			{
				return;
			}
			try
			{
				owner.BeginInvoke((MethodInvoker)delegate
				{
					if (MessageBox.Show(owner, "已接收 " + files + " 个文件到：\r\n" + dir + "\r\n\r\n现在打开文件夹吗？", "NetGate 文件传输", MessageBoxButtons.YesNo, MessageBoxIcon.Asterisk) == DialogResult.Yes)
					{
						try
						{
							Process.Start("explorer.exe", "\"" + dir + "\"");
						}
						catch
						{
						}
					}
				});
			}
			catch
			{
			}
		}

		public void SaveConfig()
		{
			try
			{
				TransferConfig.Save(LocalName, ReceiveDir);
			}
			catch
			{
			}
		}

		// 改本机显示名称：文件传输列表、聊天、控制端设备列表都会跟着变
		public void SetLocalName(string name)
		{
			string text = (name ?? "").Trim();
			if (text.Length > 40)
			{
				text = text.Substring(0, 40);
			}
			LocalName = ((text.Length == 0) ? TransferConfig.DefaultName : text);
			SaveConfig();
			Log("本机名称已改为：" + LocalName);
		}

		// 给某台电脑发一条聊天消息（TCP 短连接，走文件传输端口，不需要额外开防火墙）
		public string SendChat(TransferPeer peer, string text, out string error)
		{
			return SendChat(peer, text, DateTime.Now, out error);
		}

		// at 由调用方指定：群发时所有接收方用同一个时间，历史记录去重才能对上
		public string SendChat(TransferPeer peer, string text, DateTime at, out string error)
		{
			error = null;
			if (peer == null)
			{
				error = "没有选择接收方";
				return null;
			}
			if (string.IsNullOrEmpty(text))
			{
				error = "消息是空的";
				return null;
			}
			if (text.Length > 2000)
			{
				text = text.Substring(0, 2000);
			}
			TcpClient tcpClient = null;
			try
			{
				tcpClient = new TcpClient();
				tcpClient.NoDelay = true;
				IAsyncResult asyncResult = tcpClient.BeginConnect(peer.Ip, peer.Port, null, null);
				if (!asyncResult.AsyncWaitHandle.WaitOne(4000))
				{
					error = "连接对方超时";
					return null;
				}
				tcpClient.EndConnect(asyncResult);
				NetworkStream stream = tcpClient.GetStream();
				stream.ReadTimeout = 6000;
				stream.WriteTimeout = 6000;
				WriteLine(stream, "CHAT\t" + LocalId + "\t" + Encode(LocalName) + "\t" + Encode(Environment.MachineName) + "\t" + Encode(text) + "\t" + at.Ticks.ToString(CultureInfo.InvariantCulture));
				string text2 = ReadLine(stream);
				if (text2 == null || !text2.StartsWith("OK", StringComparison.Ordinal))
				{
					error = "对方没有应答";
					return null;
				}
				Log("已发送消息给 " + peer.Display);
				return "OK";
			}
			catch (Exception ex)
			{
				error = ex.Message;
				return null;
			}
			finally
			{
				try
				{
					if (tcpClient != null)
					{
						tcpClient.Close();
					}
				}
				catch
				{
				}
			}
		}

		/// <summary>
		/// 群发：把一条消息发给列表里所有电脑（按实例 ID 去重、跳过自己），并行发，最多等 6 秒。
		/// 返回成功台数，failed 为没送达的台数。
		/// </summary>
		public int SendChatAll(string text, List<TransferPeer> peers, out int failed)
		{
			return SendChatAll(text, peers, DateTime.Now, out failed);
		}

		public int SendChatAll(string text, List<TransferPeer> peers, DateTime at, out int failed)
		{
			failed = 0;
			if (peers == null || peers.Count == 0 || string.IsNullOrEmpty(text))
			{
				return 0;
			}
			List<TransferPeer> list = new List<TransferPeer>();
			HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (TransferPeer peer in peers)
			{
				if (peer == null || string.IsNullOrEmpty(peer.Ip) || peer.Port <= 0)
				{
					continue;
				}
				if (peer.Id == LocalId)
				{
					continue;
				}
				string text2 = ((peer.Id.Length > 0) ? peer.Id : (peer.Ip + ":" + peer.Port));
				if (hashSet.Add(text2))
				{
					list.Add(peer);
				}
			}
			if (list.Count == 0)
			{
				return 0;
			}
			int num = 0;
			int num2 = 0;
			int num3 = list.Count;
			ManualResetEvent manualResetEvent = new ManualResetEvent(false);
			foreach (TransferPeer item in list)
			{
				TransferPeer target = item;
				Thread thread = new Thread((ThreadStart)delegate
				{
					try
					{
						string error;
						if (SendChat(target, text, at, out error) != null)
						{
							Interlocked.Increment(ref num);
						}
						else
						{
							Interlocked.Increment(ref num2);
						}
					}
					catch
					{
						Interlocked.Increment(ref num2);
					}
					if (Interlocked.Decrement(ref num3) == 0)
					{
						try
						{
							manualResetEvent.Set();
						}
						catch
						{
						}
					}
				});
				thread.IsBackground = true;
				thread.Start();
			}
			manualResetEvent.WaitOne(6000);
			int num4 = num + num2;
			if (num4 < list.Count)
			{
				// 超时还没回的按失败算
				failed = list.Count - num;
				return num;
			}
			failed = num2;
			return num;
		}

		private void HandleChatLine(NetworkStream stream, TcpClient c, string line)
		{
			string[] array = line.Split('\t');
			ChatMessage chatMessage = new ChatMessage();
			if (array.Length >= 5)
			{
				chatMessage.FromId = array[1];
				chatMessage.FromName = Decode(array[2]).Trim();
				chatMessage.FromHost = Decode(array[3]).Trim();
				chatMessage.Text = Decode(array[4]);
			}
			if (chatMessage.FromName.Length == 0)
			{
				chatMessage.FromName = ((chatMessage.FromHost.Length > 0) ? chatMessage.FromHost : chatMessage.FromId);
			}
			chatMessage.At = DateTime.Now;
			if (array.Length >= 6)
			{
				long result;
				if (long.TryParse(array[5].Trim(), out result) && result > 0L)
				{
					try
					{
						// 用发送方的时间，这样各机器的历史记录时间一致、去重也能对上
						chatMessage.At = new DateTime(result);
					}
					catch
					{
					}
				}
			}
			try
			{
				IPEndPoint iPEndPoint = c.Client.RemoteEndPoint as IPEndPoint;
				if (iPEndPoint != null)
				{
					chatMessage.FromIp = iPEndPoint.Address.ToString();
				}
			}
			catch
			{
			}
			if (chatMessage.Text.Length == 0 || chatMessage.Text.Length > 4000)
			{
				WriteLine(stream, "NO");
				return;
			}
			// 控制端禁言了这台设备：消息照收不误，但不落记录、不显示
			if (IsMutedId(chatMessage.FromId) || IsMutedIp(chatMessage.FromIp))
			{
				WriteLine(stream, "OK");
				Log("已忽略被禁言设备的消息：" + chatMessage.FromName + "（" + chatMessage.FromIp + "）");
				return;
			}
			// 先回 OK 再转给界面，避免发送方等超时
			WriteLine(stream, "OK");
			AppendChatLog(chatMessage.FromName, chatMessage.At, chatMessage.Text);
			Log("收到 " + chatMessage.FromName + "（" + chatMessage.FromIp + "）的消息");
			Action<ChatMessage> handler = ChatArrived;
			if (handler != null)
			{
				try
				{
					handler(chatMessage);
				}
				catch
				{
				}
			}
		}

		public static string ChatLogPath
		{
			get
			{
				return Path.Combine(Program.DataDir, "chat.log");
			}
		}

		// 聊天记录：一行一条，制表符分隔 —— 时间<TAB>名字<TAB>内容
		// 这样既能直接看懂，也能被程序读回来做历史记录
		public static void AppendChatLog(string name, DateTime at, string text)
		{
			try
			{
				string text2 = (name ?? "").Replace("\t", " ").Replace("\r", " ").Replace("\n", " ");
				string text3 = (text ?? "").Replace("\r", " ").Replace("\n", " ");
				if (text3.Length == 0)
				{
					return;
				}
				lock (chatLogLock)
				{
					// 单文件超过 4 MB 就滚动到 chat.log.1，避免长期使用后打开窗口越来越慢
					try
					{
						FileInfo info = new FileInfo(ChatLogPath);
						if (info.Exists && info.Length > 4L * 1024L * 1024L)
						{
							string archive = ChatLogPath + ".1";
							try
							{
								if (File.Exists(archive))
								{
									File.Delete(archive);
								}
								File.Move(ChatLogPath, archive);
							}
							catch
							{
							}
						}
					}
					catch
					{
					}
					File.AppendAllText(ChatLogPath, at.ToString("yyyy-MM-dd HH:mm:ss") + "\t" + text2 + "\t" + text3 + "\r\n", new UTF8Encoding(false));
				}
			}
			catch
			{
			}
		}

		public static void ClearChatLog()
		{
			try
			{
				lock (chatLogLock)
				{
					if (File.Exists(ChatLogPath))
					{
						File.WriteAllText(ChatLogPath, "", new UTF8Encoding(false));
					}
					string archive = ChatLogPath + ".1";
					if (File.Exists(archive))
					{
						File.Delete(archive);
					}
				}
			}
			catch
			{
			}
		}

		public static ChatMessage ParseChatLogLine(string line)
		{
			try
			{
				if (string.IsNullOrEmpty(line))
				{
					return null;
				}
				line = line.TrimStart('\uFEFF');
				string[] array = line.Split('\t');
				if (array.Length < 3)
				{
					return null;
				}
				DateTime at;
				if (!DateTime.TryParseExact(array[0].Trim(), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out at))
				{
					return null;
				}
				string text = ((array.Length > 3) ? string.Join("\t", array, 2, array.Length - 2) : array[2]);
				if (string.IsNullOrEmpty(text))
				{
					return null;
				}
				ChatMessage chatMessage = new ChatMessage();
				chatMessage.At = at;
				chatMessage.FromName = array[1];
				chatMessage.Text = text;
				return chatMessage;
			}
			catch
			{
				return null;
			}
		}

		// 读最近 max 条记录（文件可能很大，只读尾巴）
		public static List<ChatMessage> LoadChatLog(int max)
		{
			List<ChatMessage> list = new List<ChatMessage>();
			try
			{
				if (max <= 0)
				{
					max = 300;
				}
				if (!File.Exists(ChatLogPath))
				{
					return list;
				}
				string text;
				bool partial = false;
				using (FileStream stream = new FileStream(ChatLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
				{
					long length = stream.Length;
					int window = (int)Math.Min(length, 512L * 1024L);
					if (window <= 0)
					{
						return list;
					}
					byte[] buffer = new byte[window];
					stream.Seek(-window, SeekOrigin.End);
					int read = 0;
					while (read < window)
					{
						int count = stream.Read(buffer, read, window - read);
						if (count <= 0)
						{
							break;
						}
						read += count;
					}
					text = Encoding.UTF8.GetString(buffer, 0, read);
					partial = window < length;
				}
				List<string> lines = new List<string>(text.Split(new string[2] { "\r\n", "\n" }, StringSplitOptions.None));
				while (lines.Count > 0 && lines[lines.Count - 1].Length == 0)
				{
					lines.RemoveAt(lines.Count - 1);
				}
				int num = Math.Max(0, lines.Count - max);
				if (partial && num == 0)
				{
					// 从文件中间开始读时，第一行通常是被截断的半行
					num = 1;
				}
				for (int i = num; i < lines.Count; i++)
				{
					ChatMessage chatMessage = ParseChatLogLine(lines[i]);
					if (chatMessage != null)
					{
						list.Add(chatMessage);
					}
				}
			}
			catch
			{
			}
			return list;
		}

		// 回应别机要历史记录：把本机最近的消息发过去
		private void HandleHistRequest(NetworkStream stream, string line)
		{
			int result = 50;
			string[] array = line.Split('\t');
			if (array.Length > 1)
			{
				int.TryParse(array[1].Trim(), out result);
			}
			if (result <= 0 || result > 200)
			{
				result = 50;
			}
			List<ChatMessage> list = LoadChatLog(result);
			WriteLine(stream, "HIST\t" + list.Count);
			for (int i = 0; i < list.Count; i++)
			{
				ChatMessage chatMessage = list[i];
				WriteLine(stream, "H\t" + Encode(chatMessage.At.ToString("yyyy-MM-dd HH:mm:ss")) + "\t" + Encode(chatMessage.FromName) + "\t" + Encode(chatMessage.Text));
			}
			WriteLine(stream, "HIST_END");
		}

		// 向某台电脑要它的历史记录（群聊“补历史”用）
		public List<ChatMessage> FetchHistory(TransferPeer peer, int max)
		{
			List<ChatMessage> list = new List<ChatMessage>();
			if (peer == null || string.IsNullOrEmpty(peer.Ip) || peer.Port <= 0)
			{
				return list;
			}
			if (max <= 0 || max > 200)
			{
				max = 50;
			}
			TcpClient tcpClient = null;
			try
			{
				tcpClient = new TcpClient();
				tcpClient.NoDelay = true;
				IAsyncResult asyncResult = tcpClient.BeginConnect(peer.Ip, peer.Port, null, null);
				if (!asyncResult.AsyncWaitHandle.WaitOne(3000))
				{
					return list;
				}
				tcpClient.EndConnect(asyncResult);
				NetworkStream stream = tcpClient.GetStream();
				stream.ReadTimeout = 6000;
				stream.WriteTimeout = 6000;
				WriteLine(stream, "HIST\t" + max.ToString(CultureInfo.InvariantCulture));
				string text = ReadLine(stream);
				if (text == null || !text.StartsWith("HIST\t", StringComparison.Ordinal))
				{
					return list;
				}
				int result;
				if (!int.TryParse(text.Substring(5).Trim(), out result) || result < 0 || result > 500)
				{
					return list;
				}
				for (int i = 0; i < result; i++)
				{
					string text2 = ReadLine(stream);
					if (text2 == null || !text2.StartsWith("H\t", StringComparison.Ordinal))
					{
						break;
					}
					string[] array = text2.Split('\t');
					if (array.Length < 4)
					{
						continue;
					}
					DateTime at;
					if (!DateTime.TryParseExact(Decode(array[1]).Trim(), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out at))
					{
						continue;
					}
					ChatMessage chatMessage = new ChatMessage();
					chatMessage.At = at;
					chatMessage.FromName = Decode(array[2]).Trim();
					chatMessage.Text = Decode(array[3]);
					if (chatMessage.Text.Length > 0)
					{
						chatMessage.FromIp = peer.Ip;
						list.Add(chatMessage);
					}
				}
				return list;
			}
			catch
			{
				return list;
			}
			finally
			{
				try
				{
					if (tcpClient != null)
					{
						tcpClient.Close();
					}
				}
				catch
				{
				}
			}
		}

		public void Log(string msg)
		{
			try
			{
				if (OnLog != null)
				{
					OnLog(msg);
				}
			}
			catch
			{
			}
			try
			{
				lock (logLock)
				{
					File.AppendAllText(Path.Combine(Program.DataDir, "transfer.log"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + msg + "\r\n", Encoding.UTF8);
				}
			}
			catch
			{
			}
		}

		private static string Encode(string s)
		{
			return Convert.ToBase64String(Encoding.UTF8.GetBytes(s ?? ""));
		}

		private static string Decode(string s)
		{
			try
			{
				return Encoding.UTF8.GetString(Convert.FromBase64String(s ?? ""));
			}
			catch
			{
				return "";
			}
		}

		private static string SafeName(string name)
		{
			name = Path.GetFileName(name ?? "");
			char[] invalidFileNameChars = Path.GetInvalidFileNameChars();
			foreach (char oldChar in invalidFileNameChars)
			{
				name = name.Replace(oldChar, '_');
			}
			if (string.IsNullOrEmpty(name))
			{
				name = "file";
			}
			return name;
		}

		private static string UniquePath(string dir, string name)
		{
			string text = Path.Combine(dir, name);
			if (!File.Exists(text))
			{
				return text;
			}
			string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(name);
			string extension = Path.GetExtension(name);
			for (int i = 1; i < 10000; i++)
			{
				string text2 = Path.Combine(dir, fileNameWithoutExtension + " (" + i + ")" + extension);
				if (!File.Exists(text2))
				{
					return text2;
				}
			}
			return Path.Combine(dir, Guid.NewGuid().ToString("N") + extension);
		}

		private static void WriteLine(NetworkStream st, string line)
		{
			byte[] bytes = Encoding.UTF8.GetBytes(line + "\n");
			st.Write(bytes, 0, bytes.Length);
			st.Flush();
		}

		private static string ReadLine(NetworkStream st)
		{
			StringBuilder stringBuilder = new StringBuilder();
			while (stringBuilder.Length < 65536)
			{
				int num = st.ReadByte();
				if (num < 0)
				{
					if (stringBuilder.Length != 0)
					{
						return stringBuilder.ToString();
					}
					return null;
				}
				switch (num)
				{
				default:
					stringBuilder.Append((char)num);
					continue;
				case 13:
					continue;
				case 10:
					break;
				}
				break;
			}
			return stringBuilder.ToString();
		}
	}
	internal static class TransferConfig
	{
		public static string DefaultName
		{
			get
			{
				return Environment.MachineName + " (" + Environment.UserName + ")";
			}
		}

		public static string DefaultDir
		{
			get
			{
				return Path.Combine(Program.DataDir, "Received");
			}
		}

		private static string FilePath
		{
			get
			{
				return Path.Combine(Program.DataDir, "transfer.ini");
			}
		}

		public static TransferConfigData Load()
		{
			TransferConfigData transferConfigData = new TransferConfigData();
			transferConfigData.Name = DefaultName;
			transferConfigData.SaveDir = DefaultDir;
			try
			{
				if (!File.Exists(FilePath))
				{
					return transferConfigData;
				}
				string[] array = File.ReadAllLines(FilePath, Encoding.UTF8);
				foreach (string text in array)
				{
					string text2 = text.Trim();
					int num = text2.IndexOf('=');
					if (num > 0)
					{
						string text3 = text2.Substring(0, num);
						string stringToUnescape = text2.Substring(num + 1);
						if (text3 == "name")
						{
							transferConfigData.Name = Uri.UnescapeDataString(stringToUnescape);
						}
						else if (text3 == "savedir")
						{
							transferConfigData.SaveDir = Uri.UnescapeDataString(stringToUnescape);
						}
					}
				}
			}
			catch
			{
			}
			if (string.IsNullOrEmpty(transferConfigData.Name))
			{
				transferConfigData.Name = DefaultName;
			}
			if (string.IsNullOrEmpty(transferConfigData.SaveDir))
			{
				transferConfigData.SaveDir = DefaultDir;
			}
			return transferConfigData;
		}

		public static void Save(string name, string dir)
		{
			try
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendLine("name=" + Uri.EscapeDataString(name ?? ""));
				stringBuilder.AppendLine("savedir=" + Uri.EscapeDataString(dir ?? ""));
				File.WriteAllText(FilePath, stringBuilder.ToString(), new UTF8Encoding(false));
			}
			catch
			{
			}
		}
	}
	internal sealed class TransferConfigData
	{
		public string Name;

		public string SaveDir;
	}
	internal class FileTransferForm : Form
	{
		private static FileTransferForm shared;

		private ListView peers;

		private Button btnScan;

		private Button btnSend;

		private Button btnDir;

		private Button btnFw;

		private Button btnClose;

		private TextBox tbManualIp;

		private Button btnAddIp;

		private Label lblInfo;

		private Label lblStatus;

		private ProgressBar progress;

		private TextBox logBox;

		private System.Windows.Forms.Timer refresh;

		private bool scanning;

		private bool sending;

		// 手动添加的电脑：自动刷新时不能被覆盖掉
		private readonly List<TransferPeer> manualPeers = new List<TransferPeer>();

		// 控制端「一体窗口」里嵌入时：成员列表可多选，一次发给多台
		public bool AdminMode;

		public void SetAdminMode()
		{
			AdminMode = true;
			peers.MultiSelect = true;
			btnSend.Text = "发送文件…（可多选）";
			// 嵌在一体窗口里时不需要“关闭”，否则会把整个标签页关空
			btnClose.Visible = false;
		}

		// 供「群聊 / 文件传输」一体窗口嵌入使用（不单独弹窗）
		internal static FileTransferForm CreateEmbedded()
		{
			FileTransferForm fileTransferForm = new FileTransferForm();
			fileTransferForm.TopLevel = false;
			fileTransferForm.FormBorderStyle = FormBorderStyle.None;
			fileTransferForm.Dock = DockStyle.Fill;
			return fileTransferForm;
		}

		// 后台线程切回界面线程：窗口已关闭/句柄已销毁时直接忽略。
		// 否则 BeginInvoke 会抛 InvalidOperationException，后台线程未捕获 → 整个进程退出
		//（就是“控制端点文件传输时突然消失、客户端又扫不到”的原因）。
		private void Post(MethodInvoker action)
		{
			try
			{
				if (base.IsDisposed || !base.IsHandleCreated)
				{
					return;
				}
				BeginInvoke(action);
			}
			catch
			{
			}
		}

		private FileTransferForm()
		{
			Text = "NetGate 文件传输";
			base.Size = new Size(740, 580);
			MinimumSize = new Size(700, 540);
			base.StartPosition = FormStartPosition.CenterParent;
			Font = new Font("Microsoft YaHei UI", 9f);
			base.Icon = NetGateIcon.Create();
			BuildUiModern();
			UiKit.AddBetaWatermark(this);
			EventHandler value = delegate
			{
				FileTransferService current2 = FileTransferService.Current;
				FileTransferService.EnsureStarted();
				current2.OnLog = delegate(string m)
				{
					AppendLog(m);
				};
				current2.OnProgress = delegate(long done, long total, string name)
				{
					ShowProgress(done, total, name);
				};
				UpdateInfo();
				LogDiagnostics();
				Scan();
				refresh = new System.Windows.Forms.Timer
				{
					Interval = 8000
				};
				refresh.Tick += delegate
				{
					if (!scanning && !sending)
					{
						Scan();
					}
				};
				refresh.Start();
			};
			base.Load += value;
			base.FormClosed += delegate
			{
				try
				{
					if (refresh != null)
					{
						refresh.Stop();
						refresh.Dispose();
					}
				}
				catch
				{
				}
				try
				{
					FileTransferService current = FileTransferService.Current;
					if (current.OnLog != null)
					{
						current.OnLog = null;
					}
					if (current.OnProgress != null)
					{
						current.OnProgress = null;
					}
				}
				catch
				{
				}
				shared = null;
			};
		}

		public static void ShowShared(IWin32Window owner)
		{
			if (shared != null && !shared.IsDisposed)
			{
				try
				{
					shared.Activate();
					return;
				}
				catch
				{
					return;
				}
			}
			shared = new FileTransferForm();
			shared.Show(owner);
		}

		private void BuildUi()
		{
			Panel panel = new Panel();
			panel.Dock = DockStyle.Top;
			panel.Height = 54;
			panel.BackColor = Color.FromArgb(15, 23, 42);
			Panel panel2 = panel;
			base.Controls.Add(panel2);
			panel2.Controls.Add(new Label
			{
				Text = "文件传输",
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 14f, FontStyle.Bold),
				Location = new Point(16, 8),
				AutoSize = true
			});
			lblInfo = new Label
			{
				ForeColor = Color.FromArgb(148, 163, 184),
				Location = new Point(140, 15),
				AutoSize = true
			};
			panel2.Controls.Add(lblInfo);
			base.Controls.Add(new Label
			{
				Text = "局域网内装有 NetGate 的电脑",
				Location = new Point(16, 64),
				AutoSize = true
			});
			peers = new ListView
			{
				Location = new Point(16, 86),
				Size = new Size(470, 300),
				View = View.Details,
				FullRowSelect = true,
				HideSelection = false
			};
			peers.Columns.Add("电脑", 230);
			peers.Columns.Add("IP 地址", 130);
			peers.Columns.Add("端口", 60);
			peers.DoubleClick += delegate
			{
				SendFiles();
			};
			base.Controls.Add(peers);
			btnScan = new Button
			{
				Text = "重新扫描",
				Location = new Point(500, 86),
				Size = new Size(210, 34)
			};
			btnSend = new Button
			{
				Text = "发送文件…",
				Location = new Point(500, 128),
				Size = new Size(210, 40)
			};
			btnDir = new Button
			{
				Text = "打开接收文件夹",
				Location = new Point(500, 176),
				Size = new Size(210, 34)
			};
			btnFw = new Button
			{
				Text = "防火墙放行 8895-8905",
				Location = new Point(500, 218),
				Size = new Size(210, 30)
			};
			btnClose = new Button
			{
				Text = "关闭",
				Location = new Point(500, 256),
				Size = new Size(210, 32)
			};
			Label label = new Label
			{
				Text = "扫不到时手动填对方 IP：",
				Location = new Point(500, 296),
				Size = new Size(210, 18),
				ForeColor = Color.FromArgb(71, 85, 105)
			};
			tbManualIp = new TextBox
			{
				Location = new Point(500, 318),
				Size = new Size(130, 25)
			};
			btnAddIp = new Button
			{
				Text = "添加",
				Location = new Point(638, 317),
				Size = new Size(72, 27)
			};
			base.Controls.Add(btnScan);
			base.Controls.Add(btnSend);
			base.Controls.Add(btnDir);
			base.Controls.Add(btnFw);
			base.Controls.Add(btnClose);
			base.Controls.Add(label);
			base.Controls.Add(tbManualIp);
			base.Controls.Add(btnAddIp);
			lblStatus = new Label
			{
				Location = new Point(16, 396),
				Size = new Size(690, 22),
				ForeColor = Color.FromArgb(71, 85, 105)
			};
			base.Controls.Add(lblStatus);
			progress = new ProgressBar
			{
				Location = new Point(16, 422),
				Size = new Size(694, 18),
				Minimum = 0,
				Maximum = 1000
			};
			base.Controls.Add(progress);
			logBox = new TextBox
			{
				Location = new Point(16, 448),
				Size = new Size(694, 80),
				Multiline = true,
				ReadOnly = true,
				ScrollBars = ScrollBars.Vertical,
				BackColor = Color.FromArgb(248, 250, 252),
				Font = new Font("Consolas", 9f)
			};
			base.Controls.Add(logBox);
			btnScan.Click += delegate
			{
				Scan();
			};
			btnSend.Click += delegate
			{
				SendFiles();
			};
			btnDir.Click += delegate
			{
				try
				{
					string receiveDir = FileTransferService.Current.ReceiveDir;
					Directory.CreateDirectory(receiveDir);
					Process.Start("explorer.exe", "\"" + receiveDir + "\"");
				}
				catch
				{
				}
			};
			btnFw.Click += delegate
			{
				FirewallFix();
			};
			btnAddIp.Click += delegate
			{
				AddManualPeer();
			};
			tbManualIp.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter)
				{
					e.SuppressKeyPress = true;
					AddManualPeer();
				}
			};
			btnClose.Click += delegate
			{
				Close();
			};
		}

		// 扫描不到但知道对方 IP 时，手动加一台（会先用 UDP 探一下，探不到也允许直接加）
		private void AddManualPeer()
		{
			string text = (tbManualIp.Text ?? "").Trim();
			if (text.Length == 0)
			{
				MessageBox.Show(this, "请先输入对方的 IP，例如 192.168.109.37。", "NetGate 文件传输", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			btnAddIp.Enabled = false;
			lblStatus.Text = "正在探测 " + text + " …";
			Thread thread = new Thread((ThreadStart)delegate
			{
				TransferPeer transferPeer = FileTransferService.Current.ProbePeer(text, 1500);
				if (transferPeer == null)
				{
					// UDP 探测不到也照样加：可能是对方防火墙拦了 UDP，但 TCP 传文件还通
					transferPeer = new TransferPeer();
					transferPeer.Id = "manual:" + text;
					transferPeer.Ip = text;
					transferPeer.Port = 8896;
					transferPeer.Name = text + "（手动添加）";
				}
				TransferPeer peer = transferPeer;
				Post(delegate
				{
					btnAddIp.Enabled = true;
					if (!ContainsPeer(manualPeers, peer))
					{
						manualPeers.Add(peer);
					}
					if (!ContainsPeerOnList(peers, peer))
					{
						ListViewItem listViewItem = new ListViewItem(peer.Display);
						listViewItem.SubItems.Add(peer.Ip);
						listViewItem.SubItems.Add(peer.Port.ToString());
						listViewItem.Tag = peer;
						peers.Items.Add(listViewItem);
						listViewItem.Selected = true;
					}
					UpdateSendButton();
					lblStatus.Text = "已添加 " + peer.Ip + ":" + peer.Port + "，选中后点“发送文件…”即可。";
					AppendLog("手动添加：" + peer.Ip + ":" + peer.Port + "（" + peer.Name + "）");
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private static bool ContainsPeer(List<TransferPeer> list, TransferPeer peer)
		{
			foreach (TransferPeer transferPeer in list)
			{
				if (transferPeer.Ip == peer.Ip && transferPeer.Port == peer.Port)
				{
					return true;
				}
			}
			return false;
		}

		private static bool ContainsPeerOnList(ListView list, TransferPeer peer)
		{
			foreach (ListViewItem item in list.Items)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && transferPeer.Ip == peer.Ip && transferPeer.Port == peer.Port)
				{
					return true;
				}
			}
			return false;
		}

		// 放行防火墙：已经在管理员进程里就直接 netsh，否则拉一个提权的自己去做
		private void FirewallFix()
		{
			List<int> list = new List<int>();
			for (int i = 8895; i <= 8905; i++)
			{
				list.Add(i);
			}
			bool flag;
			if (Program.IsAdmin())
			{
				FirewallRepairResult repair = Firewall.Repair("File", list.ToArray());
				flag = repair.Ok;
				AppendLog(repair.Message);
			}
			else
			{
				flag = false;
				try
				{
					ProcessStartInfo processStartInfo = new ProcessStartInfo();
					processStartInfo.FileName = Program.SelfPath;
					processStartInfo.Arguments = "--firewall-setup" + (Program.DebugMode ? " --debug" : "");
					processStartInfo.UseShellExecute = true;
					processStartInfo.Verb = "runas";
					Process.Start(processStartInfo);
					for (int j = 0; j < 60; j++)
					{
						if (Program.FirewallDone())
						{
							flag = true;
							break;
						}
						Thread.Sleep(100);
					}
				}
				catch (Exception ex)
				{
					Program.LogFirewall("manual firewall fix failed: " + ex.Message);
				}
			}
			AppendLog(flag ? "防火墙已放行 8895-8905（TCP+UDP）" : "防火墙放行失败，请看 UAC 弹窗或 data\\firewall.log");
			MessageBox.Show(this, flag ? "已放行文件传输端口 8895-8905（TCP+UDP）。" : "放行失败。请在 UAC 弹窗里点“是”，或右键以管理员身份运行本程序后再试；详情见 data\\firewall.log。", "NetGate 文件传输", MessageBoxButtons.OK, flag ? MessageBoxIcon.Asterisk : MessageBoxIcon.Exclamation);
		}

		private void UpdateInfo()
		{
			FileTransferService current = FileTransferService.Current;
			lblInfo.Text = "本机：" + current.LocalName + "    IP：" + Util.LanIPv4();
		}

		// 把「本机到底有没有在监听、防火墙放没放行」写进日志框，扫不到时一眼能看出问题在哪
		private void LogDiagnostics()
		{
			FileTransferService current = FileTransferService.Current;
			string text = ((current.UdpListenPort > 0) ? ("UDP " + current.UdpListenPort) : "UDP 未监听");
			AppendLog("本机监听 " + text + " / TCP " + current.TcpListenPort);
			AppendLog("发现端口 8895-8899，防火墙" + (Program.FirewallDone() ? "已放行" : "未放行（点右侧按钮放行）"));
			if (current.UdpListenPort <= 0)
			{
				AppendLog("警告：本机没有监听 UDP，别人搜不到本机。请点“防火墙放行”或退出后重新打开本程序。");
			}
		}

		private void AppendLog(string msg)
		{
			if (base.IsDisposed)
			{
				return;
			}
			try
			{
				if (base.InvokeRequired)
				{
					Post(delegate
					{
						AppendLog(msg);
					});
					return;
				}
				if (logBox.TextLength > 20000)
				{
					logBox.Clear();
				}
				logBox.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + msg + "\r\n");
				logBox.SelectionStart = logBox.TextLength;
				logBox.ScrollToCaret();
			}
			catch
			{
			}
		}

		private void ShowProgress(long done, long total, string name)
		{
			if (base.IsDisposed)
			{
				return;
			}
			try
			{
				if (base.InvokeRequired)
				{
					Post(delegate
					{
						ShowProgress(done, total, name);
					});
					return;
				}
				int value = (int)((total > 0) ? Math.Min(1000L, done * 1000 / total) : 0);
				progress.Value = value;
				lblStatus.Text = "正在传输：" + name + "   " + Util.FmtBytes(done) + " / " + Util.FmtBytes(total);
			}
			catch
			{
			}
		}

		private void Scan()
		{
			if (scanning)
			{
				return;
			}
			scanning = true;
			btnScan.Enabled = false;
			lblStatus.Text = "正在扫描局域网内的 NetGate 电脑…";
			Thread thread = new Thread((ThreadStart)delegate
			{
				List<TransferPeer> list = FileTransferService.Current.Discover(2500);
				if (list.Count == 0)
				{
					list = FileTransferService.Current.Discover(2000);
				}
				Post(delegate
				{
					scanning = false;
					btnScan.Enabled = true;
					// 手动添加的电脑在自动刷新时保留下来
					foreach (TransferPeer manual in manualPeers)
					{
						if (!ContainsPeer(list, manual))
						{
							list.Add(manual);
						}
					}
					peers.BeginUpdate();
					peers.Items.Clear();
					foreach (TransferPeer item in list)
					{
						ListViewItem value = new ListViewItem(item.Display)
						{
							SubItems = 
							{
								item.Ip,
								item.Port.ToString()
							},
							Tag = item
						};
						peers.Items.Add(value);
					}
					peers.EndUpdate();
					UpdateSendButton();
					lblStatus.Text = ((list.Count == 0) ? "没有发现其它 NetGate 电脑。请确认对方也开着本软件（用户端启动即可被发现）；仍找不到时可用右侧“手动填对方 IP”添加。" : ("发现 " + list.Count + " 台电脑，选中后点“发送文件…”。"));
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private void SendFiles()
		{
			if (sending)
			{
				return;
			}
			List<TransferPeer> list = new List<TransferPeer>();
			foreach (ListViewItem item in peers.SelectedItems)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && !list.Exists((TransferPeer x) => x.Id == transferPeer.Id))
				{
					list.Add(transferPeer);
				}
			}
			if (list.Count == 0)
			{
				MessageBox.Show(this, "请先在列表里选中接收方电脑（可按住 Ctrl / Shift 多选）。", "NetGate 文件传输", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			using (OpenFileDialog openFileDialog = new OpenFileDialog())
			{
				openFileDialog.Title = ((list.Count == 1) ? ("选择要发送给 " + list[0].Display + " 的文件") : ("选择要发送给 " + list.Count + " 台电脑的文件"));
				openFileDialog.Multiselect = true;
				openFileDialog.Filter = "所有文件 (*.*)|*.*";
				if (openFileDialog.ShowDialog(this) != DialogResult.OK)
				{
					return;
				}
				string[] files = openFileDialog.FileNames;
				sending = true;
				btnSend.Enabled = false;
				lblStatus.Text = ((list.Count == 1) ? "正在等待对方接收…" : ("正在发送到 " + list.Count + " 台电脑…"));
				Action<long, long, string> progressCb = null;
				if (list.Count == 1)
				{
					progressCb = delegate(long done, long total, string name)
					{
						ShowProgress(done, total, name);
					};
				}
				Thread thread = new Thread((ThreadStart)delegate
				{
					int ok = 0;
					int fail = 0;
					List<string> errors = new List<string>();
					object gate = new object();
					List<Thread> threads = new List<Thread>();
					foreach (TransferPeer item2 in list)
					{
						TransferPeer p = item2;
						Thread thread2 = new Thread((ThreadStart)delegate
						{
							string error;
							string text = FileTransferService.Current.Send(p, files, progressCb, out error);
							lock (gate)
							{
								if (text != null)
								{
									ok++;
								}
								else
								{
									fail++;
									errors.Add(p.Display + "：" + error);
								}
							}
						});
						thread2.IsBackground = true;
						thread2.Start();
						threads.Add(thread2);
					}
					foreach (Thread item3 in threads)
					{
						item3.Join(180000);
					}
					Post(delegate
					{
						sending = false;
						UpdateSendButton();
						if (fail == 0)
						{
							progress.Value = 1000;
							lblStatus.Text = ((list.Count == 1) ? "发送完成。" : ("已发送给 " + ok + " 台电脑。"));
							AppendLog("发送完成：" + files.Length + " 个文件 → " + ok + " 台电脑");
						}
						else
						{
							progress.Value = 0;
							lblStatus.Text = "发送完成：成功 " + ok + " 台，失败 " + fail + " 台。";
							AppendLog("发送完成：成功 " + ok + " 台，失败 " + fail + " 台（" + string.Join("；", errors.ToArray()) + "）");
						}
					});
				});
				thread.IsBackground = true;
				thread.Start();
			}
		}
		private void BuildUiModern()
		{
			SuspendLayout();
			UiKit.Apply(this);
			DoubleBuffered = true;
			Text = "NetGate 文件传输";
			base.Size = new Size(900, 680);
			MinimumSize = new Size(840, 620);

			TableLayoutPanel root = new TableLayoutPanel();
			root.Dock = DockStyle.Fill;
			root.ColumnCount = 1;
			root.RowCount = 2;
			root.BackColor = UiKit.Bg;
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64f));
			root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			base.Controls.Add(root);

			Panel header = new Panel();
			header.Dock = DockStyle.Fill;
			header.BackColor = UiKit.Header;
			root.Controls.Add(header, 0, 0);
			header.Controls.Add(new Label
			{
				Text = "文件传输",
				ForeColor = Color.White,
				Font = UiKit.Title,
				AutoSize = true,
				Location = new Point(20, 18)
			});
			FlowLayoutPanel headerRight = new FlowLayoutPanel();
			headerRight.Dock = DockStyle.Right;
			headerRight.Width = 560;
			headerRight.FlowDirection = FlowDirection.RightToLeft;
			headerRight.WrapContents = false;
			headerRight.BackColor = UiKit.Header;
			headerRight.Padding = new Padding(0, 22, 20, 0);
			header.Controls.Add(headerRight);
			lblInfo = new Label();
			lblInfo.ForeColor = UiKit.HeaderText;
			lblInfo.Font = UiKit.Body;
			lblInfo.AutoSize = true;
			lblInfo.Margin = new Padding(0);
			headerRight.Controls.Add(lblInfo);

			Panel body = new Panel();
			body.Dock = DockStyle.Fill;
			body.BackColor = UiKit.Bg;
			body.Padding = new Padding(16, 16, 16, 16);
			root.Controls.Add(body, 0, 1);

			TableLayoutPanel layout = new TableLayoutPanel();
			layout.Dock = DockStyle.Fill;
			layout.ColumnCount = 1;
			layout.RowCount = 2;
			layout.BackColor = UiKit.Bg;
			layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 200f));
			body.Controls.Add(layout);

			TableLayoutPanel split = new TableLayoutPanel();
			split.Dock = DockStyle.Fill;
			split.ColumnCount = 2;
			split.RowCount = 1;
			split.BackColor = UiKit.Bg;
			split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
			split.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 280f));
			split.Margin = new Padding(0, 0, 0, 12);
			layout.Controls.Add(split, 0, 0);

			Panel listCard = UiKit.CardPanel();
			listCard.Dock = DockStyle.Fill;
			listCard.Margin = new Padding(0, 0, 12, 0);
			listCard.Padding = new Padding(16, 12, 16, 16);
			split.Controls.Add(listCard, 0, 0);

			TableLayoutPanel listLayout = new TableLayoutPanel();
			listLayout.Dock = DockStyle.Fill;
			listLayout.ColumnCount = 1;
			listLayout.RowCount = 2;
			listLayout.BackColor = UiKit.Card;
			listLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32f));
			listLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			listCard.Controls.Add(listLayout);
			listLayout.Controls.Add(new Label
			{
				Text = "局域网电脑",
				Font = UiKit.SubTitle,
				ForeColor = UiKit.TextColor,
				AutoSize = true,
				Margin = new Padding(0)
			}, 0, 0);

			peers = new ListView();
			peers.Dock = DockStyle.Fill;
			peers.View = View.Details;
			peers.MultiSelect = false;
			UiKit.StyleList(peers);
			peers.Columns.Add("电脑", 230);
			peers.Columns.Add("IP 地址", 140);
			peers.Columns.Add("端口", 70);
			listLayout.Controls.Add(peers, 0, 1);

			Panel sideCard = UiKit.CardPanel();
			sideCard.Dock = DockStyle.Fill;
			sideCard.Padding = new Padding(16, 14, 16, 14);
			split.Controls.Add(sideCard, 1, 0);

			FlowLayoutPanel side = new FlowLayoutPanel();
			side.Dock = DockStyle.Fill;
			side.FlowDirection = FlowDirection.TopDown;
			side.WrapContents = false;
			side.BackColor = UiKit.Card;
			side.Margin = new Padding(0);
			sideCard.Controls.Add(side);

			btnScan = UiKit.SecondaryButton("重新扫描");
			btnScan.Width = 236;
			btnScan.Margin = new Padding(0, 0, 0, 8);
			btnSend = UiKit.PrimaryButton("发送文件…");
			btnSend.Width = 236;
			btnSend.Height = 40;
			btnSend.Margin = new Padding(0, 0, 0, 8);
			btnDir = UiKit.SecondaryButton("打开接收文件夹");
			btnDir.Width = 236;
			btnDir.Margin = new Padding(0, 0, 0, 8);
			btnFw = UiKit.SecondaryButton("放行防火墙端口");
			btnFw.Width = 236;
			btnFw.Margin = new Padding(0, 0, 0, 16);
			tbManualIp = new TextBox();
			tbManualIp.Width = 236;
			tbManualIp.BorderStyle = BorderStyle.FixedSingle;
			tbManualIp.Margin = new Padding(0, 0, 0, 8);
			btnAddIp = UiKit.SecondaryButton("按 IP 添加");
			btnAddIp.Width = 236;
			btnAddIp.Margin = new Padding(0, 0, 0, 16);
			btnClose = UiKit.SecondaryButton("关闭");
			btnClose.Width = 236;
			btnClose.Margin = new Padding(0);
			side.Controls.Add(btnScan);
			side.Controls.Add(btnSend);
			side.Controls.Add(btnDir);
			side.Controls.Add(btnFw);
			side.Controls.Add(tbManualIp);
			side.Controls.Add(btnAddIp);
			side.Controls.Add(btnClose);
			UiKit.SetPlaceholder(tbManualIp, "对方 IP 地址");

			Panel bottomCard = UiKit.CardPanel();
			bottomCard.Dock = DockStyle.Fill;
			bottomCard.Margin = new Padding(0, 12, 0, 0);
			bottomCard.Padding = new Padding(16, 12, 16, 12);
			layout.Controls.Add(bottomCard, 0, 1);

			TableLayoutPanel bottom = new TableLayoutPanel();
			bottom.Dock = DockStyle.Fill;
			bottom.ColumnCount = 1;
			bottom.RowCount = 3;
			bottom.BackColor = UiKit.Card;
			bottom.RowStyles.Add(new RowStyle(SizeType.Absolute, 26f));
			bottom.RowStyles.Add(new RowStyle(SizeType.Absolute, 22f));
			bottom.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			bottomCard.Controls.Add(bottom);

			lblStatus = new Label();
			lblStatus.Dock = DockStyle.Fill;
			lblStatus.AutoSize = false;
			lblStatus.TextAlign = ContentAlignment.MiddleLeft;
			lblStatus.ForeColor = UiKit.Muted;
			lblStatus.Margin = new Padding(0);
			bottom.Controls.Add(lblStatus, 0, 0);

			progress = new ProgressBar();
			progress.Dock = DockStyle.Fill;
			progress.Minimum = 0;
			progress.Maximum = 1000;
			progress.Margin = new Padding(0, 2, 0, 6);
			bottom.Controls.Add(progress, 0, 1);

			logBox = new TextBox();
			logBox.Dock = DockStyle.Fill;
			logBox.Multiline = true;
			logBox.ReadOnly = true;
			logBox.ScrollBars = ScrollBars.Vertical;
			logBox.BackColor = Color.FromArgb(250, 251, 253);
			logBox.BorderStyle = BorderStyle.FixedSingle;
			logBox.Font = UiKit.Mono;
			logBox.Margin = new Padding(0);
			bottom.Controls.Add(logBox, 0, 2);

			btnScan.Click += delegate
			{
				Scan();
			};
			btnSend.Click += delegate
			{
				SendFiles();
			};
			btnDir.Click += delegate
			{
				try
				{
					string receiveDir = FileTransferService.Current.ReceiveDir;
					Directory.CreateDirectory(receiveDir);
					Process.Start("explorer.exe", "\"" + receiveDir + "\"");
				}
				catch
				{
				}
			};
			btnFw.Click += delegate
			{
				FirewallFix();
			};
			btnAddIp.Click += delegate
			{
				AddManualPeer();
			};
			tbManualIp.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter)
				{
					e.SuppressKeyPress = true;
					AddManualPeer();
				}
			};
			btnClose.Click += delegate
			{
				Close();
			};
			peers.DoubleClick += delegate
			{
				SendFiles();
			};
			peers.SelectedIndexChanged += delegate
			{
				UpdateSendButton();
			};
			UpdateSendButton();
			ResumeLayout();
		}

		private void UpdateSendButton()
		{
			if (btnSend != null)
			{
				btnSend.Enabled = !sending && peers != null && peers.SelectedItems.Count > 0;
			}
		}
	}
	internal class NameDialog : Form
	{
		private string value;

		private NameDialog(string initial)
		{
			Text = "设置我的名称";
			base.Size = new Size(460, 250);
			base.StartPosition = FormStartPosition.CenterParent;
			base.FormBorderStyle = FormBorderStyle.FixedDialog;
			base.MaximizeBox = false;
			base.MinimizeBox = false;
			UiKit.Apply(this);
			base.BackColor = Color.White;
			base.Padding = new Padding(24, 20, 24, 20);

			TableLayoutPanel layout = new TableLayoutPanel();
			layout.Dock = DockStyle.Fill;
			layout.ColumnCount = 1;
			layout.RowCount = 3;
			layout.BackColor = Color.White;
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 74f));
			layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
			base.Controls.Add(layout);

			TableLayoutPanel inputRow = new TableLayoutPanel();
			inputRow.Dock = DockStyle.Fill;
			inputRow.ColumnCount = 1;
			inputRow.RowCount = 2;
			inputRow.BackColor = Color.White;
			inputRow.RowStyles.Add(new RowStyle(SizeType.Absolute, 24f));
			inputRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			layout.Controls.Add(inputRow, 0, 0);
			inputRow.Controls.Add(UiKit.FieldLabel("显示名称"), 0, 0);

			TextBox tb = new TextBox();
			tb.Dock = DockStyle.Fill;
			tb.Font = new Font("Microsoft YaHei UI", 10f);
			tb.BorderStyle = BorderStyle.FixedSingle;
			tb.Text = initial ?? "";
			tb.Margin = new Padding(0);
			inputRow.Controls.Add(tb, 0, 1);

			FlowLayoutPanel buttons = new FlowLayoutPanel();
			buttons.Dock = DockStyle.Fill;
			buttons.FlowDirection = FlowDirection.RightToLeft;
			buttons.WrapContents = false;
			buttons.BackColor = Color.White;
			layout.Controls.Add(buttons, 0, 2);

			Button button = UiKit.PrimaryButton("确定");
			button.Width = 88;
			buttons.Controls.Add(button);
			Button cancelButton = UiKit.SecondaryButton("取消");
			cancelButton.Width = 88;
			cancelButton.DialogResult = DialogResult.Cancel;
			buttons.Controls.Add(cancelButton);
			base.CancelButton = cancelButton;
			base.AcceptButton = button;
			button.Click += delegate
			{
				string text = tb.Text.Trim();
				if (text.Length == 0)
				{
					MessageBox.Show("名称不能为空。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
					return;
				}
				value = text;
				base.DialogResult = DialogResult.OK;
				Close();
			};
			tb.SelectAll();
		}

		public static string Show(IWin32Window owner, string initial)
		{
			using (NameDialog nameDialog = new NameDialog(initial))
			{
				return (nameDialog.ShowDialog(owner) == DialogResult.OK) ? nameDialog.value : null;
			}
		}
	}
	internal class ChatForm : Form
	{
		private static ChatForm shared;

		// 只有控制端打开群聊窗口时才会设置：用来在群聊里禁言/解禁某台电脑
		public static NetGateServer AdminServer;

		public static AdminConfig AdminCfg;

		private ListView peers;

		private Button btnScan;

		private Button btnMute;

		private TextBox logBox;

		private TextBox tbInput;

		private Button btnSend;

		private Button btnClear;

		private TextBox tbMyName;

		private Button btnSaveName;

		private Label lblStatus;

		private Label lblMine;

		private System.Windows.Forms.Timer refresh;

		private bool scanning;

		private bool sending;

		private bool historySynced;

		private readonly Dictionary<string, string> historyKeys = new Dictionary<string, string>(StringComparer.Ordinal);

		public static bool IsOpen
		{
			get
			{
				return shared != null && !shared.IsDisposed && shared.Visible;
			}
		}

		private ChatForm()
		{
			Text = "NetGate 局域网群聊";
			base.Size = new Size(820, 620);
			base.MinimumSize = new Size(780, 580);
			base.StartPosition = FormStartPosition.CenterParent;
			Font = new Font("Microsoft YaHei UI", 9f);
			base.Icon = NetGateIcon.Create();
			BuildUiModern();
			UiKit.AddBetaWatermark(this);
			base.Load += delegate
			{
				FileTransferService.EnsureStarted();
				FileTransferService.ChatArrived += OnChatArrived;
				UpdateMine();
				// 先显示本机保存的历史记录（data\chat.log），再扫描成员、补别人那边的历史
				ShowHistory(FileTransferService.LoadChatLog(300), true);
				Scan();
				refresh = new System.Windows.Forms.Timer
				{
					Interval = 8000
				};
				refresh.Tick += delegate
				{
					if (!scanning)
					{
						Scan();
					}
				};
				refresh.Start();
			};
			base.FormClosed += delegate
			{
				try
				{
					if (refresh != null)
					{
						refresh.Stop();
						refresh.Dispose();
					}
				}
				catch
				{
				}
				try
				{
					FileTransferService.ChatArrived -= OnChatArrived;
				}
				catch
				{
				}
				AdminServer = null;
				AdminCfg = null;
				shared = null;
			};
		}

		public static void ShowShared(IWin32Window owner)
		{
			if (shared != null && !shared.IsDisposed)
			{
				try
				{
					shared.Activate();
					return;
				}
				catch
				{
					return;
				}
			}
			shared = new ChatForm();
			shared.Show(owner);
		}

		// 控制端用的入口：带上引擎和配置，群聊窗口里就能禁言/解禁
		public static void ShowShared(IWin32Window owner, NetGateServer server, AdminConfig cfg)
		{
			AdminServer = server;
			AdminCfg = cfg;
			ShowShared(owner);
		}

		// 供「群聊 / 文件传输」一体窗口嵌入使用
		internal static ChatForm CreateEmbedded()
		{
			ChatForm chatForm = new ChatForm();
			chatForm.TopLevel = false;
			chatForm.FormBorderStyle = FormBorderStyle.None;
			chatForm.Dock = DockStyle.Fill;
			return chatForm;
		}

		private void BuildUi()
		{
			Panel panel = new Panel();
			panel.Dock = DockStyle.Top;
			panel.Height = 54;
			panel.BackColor = Color.FromArgb(15, 23, 42);
			base.Controls.Add(panel);
			panel.Controls.Add(new Label
			{
				Text = "局域网群聊",
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 14f, FontStyle.Bold),
				Location = new Point(16, 8),
				AutoSize = true
			});
			lblMine = new Label
			{
				ForeColor = Color.FromArgb(148, 163, 184),
				Location = new Point(150, 15),
				AutoSize = true
			};
			panel.Controls.Add(lblMine);
			base.Controls.Add(new Label
			{
				Text = "在线成员（群聊消息发给这里所有人）",
				Location = new Point(16, 66),
				AutoSize = true
			});
			bool adminMode = (AdminServer != null);
			peers = new ListView
			{
				Location = new Point(16, 88),
				Size = new Size(270, 360),
				View = View.Details,
				FullRowSelect = true,
				HideSelection = false,
				MultiSelect = adminMode
			};
			peers.Columns.Add("名字", 150);
			peers.Columns.Add("IP", 100);
			base.Controls.Add(peers);
			btnScan = new Button
			{
				Text = "重新扫描",
				Location = new Point(16, 456),
				Size = new Size(150, 30)
			};
			base.Controls.Add(btnScan);
			btnMute = new Button
			{
				Text = "禁言/解禁",
				Location = new Point(172, 456),
				Size = new Size(114, 30),
				Visible = adminMode
			};
			base.Controls.Add(btnMute);
			base.Controls.Add(new Label
			{
				Text = "我的名称（对方看到的名字）",
				Location = new Point(16, 494),
				AutoSize = true
			});
			tbMyName = new TextBox
			{
				Location = new Point(16, 514),
				Size = new Size(168, 26)
			};
			base.Controls.Add(tbMyName);
			btnSaveName = new Button
			{
				Text = "保存名称",
				Location = new Point(190, 513),
				Size = new Size(76, 28)
			};
			base.Controls.Add(btnSaveName);
			lblStatus = new Label
			{
				Location = new Point(16, 552),
				Size = new Size(770, 22),
				ForeColor = Color.FromArgb(71, 85, 105)
			};
			base.Controls.Add(lblStatus);
			logBox = new TextBox
			{
				Location = new Point(300, 88),
				Size = new Size(502, 330),
				Multiline = true,
				ReadOnly = true,
				ScrollBars = ScrollBars.Vertical,
				BackColor = Color.FromArgb(248, 250, 252),
				Font = new Font("Microsoft YaHei UI", 10f)
			};
			base.Controls.Add(logBox);
			tbInput = new TextBox
			{
				Location = new Point(300, 428),
				Size = new Size(414, 28),
				Font = new Font("Microsoft YaHei UI", 10f)
			};
			base.Controls.Add(tbInput);
			btnSend = new Button
			{
				Text = "群发",
				Location = new Point(722, 426),
				Size = new Size(80, 30),
				BackColor = Color.FromArgb(37, 99, 235),
				ForeColor = Color.White,
				FlatStyle = FlatStyle.Flat
			};
			btnSend.FlatAppearance.BorderSize = 0;
			base.Controls.Add(btnSend);
			base.Controls.Add(new Label
			{
				Text = "回车群发：消息会发给左边所有电脑；只发文字，仅限可信局域网。",
				Location = new Point(300, 462),
				Size = new Size(410, 20),
				ForeColor = Color.FromArgb(100, 116, 139)
			});
			btnClear = new Button
			{
				Text = "清屏",
				Location = new Point(722, 462),
				Size = new Size(80, 26)
			};
			base.Controls.Add(btnClear);
			btnScan.Click += delegate
			{
				Scan();
			};
			btnMute.Click += delegate
			{
				ToggleMuteSelected();
			};
			btnSend.Click += delegate
			{
				SendMessage();
			};
			btnClear.Click += delegate
			{
				logBox.Clear();
			};
			btnSaveName.Click += delegate
			{
				SaveName();
			};
			tbMyName.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter)
				{
					e.SuppressKeyPress = true;
					SaveName();
				}
			};
			tbInput.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter && !e.Shift)
				{
					e.SuppressKeyPress = true;
					SendMessage();
				}
			};
		}

		private void UpdateMine()
		{
			FileTransferService current = FileTransferService.Current;
			lblMine.Text = "我的名称：" + current.LocalName + "    IP：" + Util.LanIPv4();
			if (!tbMyName.Focused)
			{
				tbMyName.Text = current.LocalName;
			}
		}

		private void SaveName()
		{
			string text = tbMyName.Text.Trim();
			if (text.Length == 0)
			{
				MessageBox.Show(this, "名称不能为空。", "NetGate 局域网聊天", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			FileTransferService.Current.SetLocalName(text);
			UpdateMine();
			AppendLog("[系统] 名称已改为：" + FileTransferService.Current.LocalName + "（对方重新扫描即可看到，控制端几秒内刷新）");
			lblStatus.Text = "名称已保存：" + FileTransferService.Current.LocalName;
		}

		private void OnChatArrived(ChatMessage m)
		{
			if (base.IsDisposed)
			{
				return;
			}
			try
			{
				if (base.InvokeRequired)
				{
					BeginInvoke((MethodInvoker)delegate
					{
						OnChatArrived(m);
					});
					return;
				}
				string key = ChatKey(m);
				if (historyKeys.ContainsKey(key))
				{
					// 已经在历史/刚才显示过，别重复刷一行
					return;
				}
				historyKeys[key] = "";
				AppendLog(FormatLine(m));
				lblStatus.Text = "收到 " + m.FromName + " 的群聊消息";
				if (!HasPeer(m.FromId))
				{
					// 新面孔：按来源 IP 探一下它的端口，方便直接回复
					string ip = m.FromIp;
					Thread thread = new Thread((ThreadStart)delegate
					{
						TransferPeer transferPeer = FileTransferService.Current.ProbePeer(ip, 1200);
						if (transferPeer == null)
						{
							return;
						}
						try
						{
							BeginInvoke((MethodInvoker)delegate
							{
								AddPeer(transferPeer);
							});
						}
						catch
						{
						}
					});
					thread.IsBackground = true;
					thread.Start();
				}
			}
			catch
			{
			}
		}

		// 后台线程安全地切回界面线程：窗口已经关掉时直接忽略，别抛到后台线程
		private void SafeInvoke(MethodInvoker action)
		{
			try
			{
				if (base.IsDisposed || !base.IsHandleCreated)
				{
					return;
				}
				BeginInvoke(action);
			}
			catch
			{
			}
		}

		private static string ChatKey(ChatMessage m)
		{
			return m.At.ToString("yyyy-MM-dd HH:mm:ss") + "|" + m.FromName + "|" + m.Text;
		}

		// 一行历史/消息的显示格式
		private static string FormatLine(ChatMessage m)
		{
			string text = ((m.FromName == FileTransferService.Current.LocalName) ? "我" : m.FromName);
			string text2 = (string.IsNullOrEmpty(m.FromIp) ? "" : ("（" + m.FromIp + "）"));
			return "[" + m.At.ToString("HH:mm:ss") + "] " + text + text2 + "：" + m.Text;
		}

		// 把历史记录铺到窗口里（按时间升序）
		private void ShowHistory(List<ChatMessage> list, bool clearFirst)
		{
			if (list == null || list.Count == 0)
			{
				return;
			}
			try
			{
				list.Sort(delegate(ChatMessage a, ChatMessage b)
				{
					return a.At.CompareTo(b.At);
				});
				StringBuilder stringBuilder = new StringBuilder();
				foreach (ChatMessage item in list)
				{
					stringBuilder.Append(FormatLine(item)).Append("\r\n");
					historyKeys[ChatKey(item)] = "";
				}
				if (clearFirst)
				{
					logBox.Text = stringBuilder.ToString();
				}
				else
				{
					logBox.Text = stringBuilder.ToString() + logBox.Text;
				}
				logBox.SelectionStart = logBox.TextLength;
				logBox.ScrollToCaret();
			}
			catch
			{
			}
		}

		// 向成员要一遍历史，补上"窗口没开时 / 本机没开时"漏掉的消息
		private void SyncHistory(List<TransferPeer> memberList)
		{
			if (historySynced || memberList == null || memberList.Count == 0)
			{
				return;
			}
			historySynced = true;
			List<TransferPeer> list = new List<TransferPeer>();
			foreach (TransferPeer item in memberList)
			{
				if (item != null && item.Id != FileTransferService.Current.LocalId)
				{
					list.Add(item);
				}
				if (list.Count >= 6)
				{
					break;
				}
			}
			if (list.Count == 0)
			{
				return;
			}
			Thread thread = new Thread((ThreadStart)delegate
			{
				Dictionary<string, ChatMessage> dictionary = new Dictionary<string, ChatMessage>(StringComparer.Ordinal);
				foreach (ChatMessage item2 in FileTransferService.LoadChatLog(300))
				{
					dictionary[ChatKey(item2)] = item2;
				}
				List<ChatMessage> list2 = new List<ChatMessage>();
				foreach (TransferPeer item3 in list)
				{
					foreach (ChatMessage item4 in FileTransferService.Current.FetchHistory(item3, 60))
					{
						string text = ChatKey(item4);
						if (!dictionary.ContainsKey(text))
						{
							dictionary[text] = item4;
							list2.Add(item4);
						}
					}
				}
				if (list2.Count == 0)
				{
					return;
				}
				list2.Sort(delegate(ChatMessage a, ChatMessage b)
				{
					return a.At.CompareTo(b.At);
				});
				foreach (ChatMessage item5 in list2)
				{
					FileTransferService.AppendChatLog(item5.FromName, item5.At, item5.Text);
				}
				SafeInvoke(delegate
				{
					ShowHistory(list2, false);
					lblStatus.Text = "已补上 " + list2.Count + " 条历史记录。";
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private bool HasPeer(string id)
		{
			foreach (ListViewItem item in peers.Items)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && transferPeer.Id == id)
				{
					return true;
				}
			}
			return false;
		}

		private void AddPeer(TransferPeer peer)
		{
			if (peer == null || HasPeer(peer.Id))
			{
				return;
			}
			string text = string.IsNullOrEmpty(peer.Name) ? peer.Ip : peer.Name;
			if (IsPeerMuted(peer))
			{
				text += "（已禁言）";
			}
			ListViewItem listViewItem = new ListViewItem(text);
			listViewItem.SubItems.Add(peer.Ip);
			listViewItem.Tag = peer;
			peers.Items.Add(listViewItem);
		}

		// 控制端点“禁言/解禁”：可多选，按选中成员的 IP 找到设备
		private void ToggleMuteSelected()
		{
			if (AdminServer == null)
			{
				return;
			}
			List<TransferPeer> list = SelectedPeers();
			if (list.Count == 0)
			{
				MessageBox.Show(this, "请先在左边选中电脑（可按住 Ctrl / Shift 多选），再点“禁言/解禁”。", "NetGate 群聊", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			bool flag = false;
			foreach (TransferPeer item in list)
			{
				Device device = AdminServer.FindByIp(item.Ip);
				if (device != null)
				{
					lock (device.Sync)
					{
						if (!device.ChatMuted)
						{
							flag = true;
						}
					}
				}
			}
			int num = 0;
			foreach (TransferPeer item2 in list)
			{
				Device device2 = AdminServer.FindByIp(item2.Ip);
				if (device2 == null)
				{
					continue;
				}
				AdminServer.SetChatMuted(device2.Mac, flag);
				if (AdminCfg != null)
				{
					if (flag)
					{
						AdminCfg.Muted[device2.Mac] = true;
					}
					else
					{
						AdminCfg.Muted.Remove(device2.Mac);
					}
				}
				num++;
			}
			if (AdminCfg != null)
			{
				AdminCfg.Save();
			}
			FileTransferService.SetMutedIps(AdminServer.MutedIps());
			RefreshPeerLabels();
			AppendLog("[系统] " + (flag ? "已禁言 " : "已解除禁言 ") + num + " 台电脑" + (flag ? "（控制端不再显示它们的群聊消息）" : ""));
			lblStatus.Text = (flag ? "已禁言 " : "已解除禁言 ") + num + " 台电脑。";
		}

		// 左边选中的成员（跳过自己）
		private List<TransferPeer> SelectedPeers()
		{
			List<TransferPeer> list = new List<TransferPeer>();
			foreach (ListViewItem item in peers.SelectedItems)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && transferPeer.Id != FileTransferService.Current.LocalId)
				{
					list.Add(transferPeer);
				}
			}
			return list;
		}

		private void RefreshPeerLabels()
		{
			foreach (ListViewItem item in peers.Items)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null)
				{
					string text = string.IsNullOrEmpty(transferPeer.Name) ? transferPeer.Ip : transferPeer.Name;
					item.Text = text + (IsPeerMuted(transferPeer) ? "（已禁言）" : "");
				}
			}
		}

		// 一次把文件发给选中的多台电脑（每台各发一份，互不影响）
		private bool IsPeerMuted(TransferPeer peer)
		{
			if (AdminServer == null || peer == null)
			{
				return false;
			}
			Device device = AdminServer.FindByIp(peer.Ip);
			if (device == null)
			{
				return false;
			}
			lock (device.Sync)
			{
				return device.ChatMuted;
			}
		}

		private void AppendLog(string msg)
		{
			if (base.IsDisposed)
			{
				return;
			}
			try
			{
				if (base.InvokeRequired)
				{
					BeginInvoke((MethodInvoker)delegate
					{
						AppendLog(msg);
					});
					return;
				}
				if (logBox.TextLength > 40000)
				{
					logBox.Clear();
				}
				logBox.AppendText(msg + "\r\n");
				logBox.SelectionStart = logBox.TextLength;
				logBox.ScrollToCaret();
			}
			catch
			{
			}
		}

		private void Scan()
		{
			if (scanning)
			{
				return;
			}
			scanning = true;
			btnScan.Enabled = false;
			lblStatus.Text = "正在扫描局域网内的 NetGate 电脑…";
			Thread thread = new Thread((ThreadStart)delegate
			{
				List<TransferPeer> list = FileTransferService.Current.Discover(2500);
				SafeInvoke(delegate
				{
					scanning = false;
					btnScan.Enabled = true;
					List<string> selectedIds = new List<string>();
					foreach (ListViewItem item in peers.SelectedItems)
					{
						TransferPeer selected = item.Tag as TransferPeer;
						if (selected != null && !selectedIds.Contains(selected.Id))
						{
							selectedIds.Add(selected.Id);
						}
					}
					peers.BeginUpdate();
					peers.Items.Clear();
					foreach (TransferPeer item in list)
					{
						AddPeer(item);
					}
					peers.EndUpdate();
					if (selectedIds.Count > 0)
					{
						foreach (ListViewItem item2 in peers.Items)
						{
							TransferPeer transferPeer = item2.Tag as TransferPeer;
							if (transferPeer != null && selectedIds.Contains(transferPeer.Id))
							{
								item2.Selected = true;
							}
						}
					}
					lblStatus.Text = ((list.Count == 0) ? "没有发现其它 NetGate 电脑。请确认对方也开着本软件（用户端启动即可被发现）。" : ("群聊成员 " + list.Count + " 台，输入消息回车即可群发。"));
					SyncHistory(list);
					UpdateMuteButton();
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		// 群聊：不再选人，直接发给列表里的所有电脑（含控制端和所有用户端）
		private void SendMessage()
		{
			if (sending)
			{
				return;
			}
			string text = tbInput.Text.Trim();
			if (text.Length == 0)
			{
				tbInput.Focus();
				return;
			}
			List<TransferPeer> targets = new List<TransferPeer>();
			foreach (ListViewItem item in peers.Items)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && transferPeer.Id != FileTransferService.Current.LocalId)
				{
					targets.Add(transferPeer);
				}
			}
			sending = true;
			btnSend.Enabled = false;
			tbInput.Clear();
			DateTime at = DateTime.Now;
			ChatMessage chatMessage = new ChatMessage();
			chatMessage.At = at;
			chatMessage.FromName = FileTransferService.Current.LocalName;
			chatMessage.Text = text;
			AppendLog(FormatLine(chatMessage));
			lblStatus.Text = "正在群发…";
			Thread thread = new Thread((ThreadStart)delegate
			{
				List<TransferPeer> list = targets;
				if (list.Count == 0)
				{
					// 列表还是空的：现扫一次，尽量把消息发出去
					foreach (TransferPeer item2 in FileTransferService.Current.Discover(1500))
					{
						if (item2.Id != FileTransferService.Current.LocalId)
						{
							list.Add(item2);
						}
					}
				}
				int failed;
				int num = FileTransferService.Current.SendChatAll(text, list, at, out failed);
				if (num > 0)
				{
					// 自己发的也写进记录：下次打开窗口能看到，别人补历史也能拿到
					FileTransferService.AppendChatLog(FileTransferService.Current.LocalName, at, text);
				}
				SafeInvoke(delegate
				{
					sending = false;
					btnSend.Enabled = true;
					if (num == 0)
					{
						AppendLog("[系统] 群发失败：没有可送达的电脑（对方可能没开本软件）");
						lblStatus.Text = "群发失败：没有可送达的电脑。点「重新扫描」再试。";
					}
					else
					{
						AppendLog("[系统] 群发结果：送达 " + num + " 台" + ((failed > 0) ? ("，" + failed + " 台未送达") : "") + "。");
						lblStatus.Text = "已群发给 " + num + " 台电脑" + ((failed > 0) ? ("（" + failed + " 台未送达）") : "") + "。";
						if (failed > 0)
						{
							// 有掉线的，重新扫一遍把成员刷干净
							Scan();
						}
					}
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private void BuildUiModern()
		{
			SuspendLayout();
			UiKit.Apply(this);
			DoubleBuffered = true;
			Text = "NetGate 局域网群聊";
			base.Size = new Size(920, 700);
			MinimumSize = new Size(860, 620);

			TableLayoutPanel root = new TableLayoutPanel();
			root.Dock = DockStyle.Fill;
			root.ColumnCount = 1;
			root.RowCount = 3;
			root.BackColor = UiKit.Bg;
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64f));
			root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
			base.Controls.Add(root);

			Panel header = new Panel();
			header.Dock = DockStyle.Fill;
			header.BackColor = UiKit.Header;
			root.Controls.Add(header, 0, 0);
			header.Controls.Add(new Label
			{
				Text = "局域网群聊",
				ForeColor = Color.White,
				Font = UiKit.Title,
				AutoSize = true,
				Location = new Point(20, 18)
			});
			FlowLayoutPanel headerRight = new FlowLayoutPanel();
			headerRight.Dock = DockStyle.Right;
			headerRight.Width = 560;
			headerRight.FlowDirection = FlowDirection.RightToLeft;
			headerRight.WrapContents = false;
			headerRight.BackColor = UiKit.Header;
			headerRight.Padding = new Padding(0, 22, 20, 0);
			header.Controls.Add(headerRight);
			lblMine = new Label();
			lblMine.ForeColor = UiKit.HeaderText;
			lblMine.Font = UiKit.Body;
			lblMine.AutoSize = true;
			lblMine.Margin = new Padding(0);
			headerRight.Controls.Add(lblMine);

			Panel body = new Panel();
			body.Dock = DockStyle.Fill;
			body.BackColor = UiKit.Bg;
			body.Padding = new Padding(16, 16, 16, 12);
			root.Controls.Add(body, 0, 1);

			TableLayoutPanel split = new TableLayoutPanel();
			split.Dock = DockStyle.Fill;
			split.ColumnCount = 2;
			split.RowCount = 1;
			split.BackColor = UiKit.Bg;
			split.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 320f));
			split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
			body.Controls.Add(split);

			bool adminMode = (AdminServer != null);

			Panel leftCard = UiKit.CardPanel();
			leftCard.Dock = DockStyle.Fill;
			leftCard.Margin = new Padding(0, 0, 12, 0);
			leftCard.Padding = new Padding(16, 12, 16, 12);
			split.Controls.Add(leftCard, 0, 0);

			TableLayoutPanel leftLayout = new TableLayoutPanel();
			leftLayout.Dock = DockStyle.Fill;
			leftLayout.ColumnCount = 1;
			leftLayout.RowCount = 4;
			leftLayout.BackColor = UiKit.Card;
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34f));
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
			leftCard.Controls.Add(leftLayout);

			Panel memberTitle = new Panel();
			memberTitle.Dock = DockStyle.Fill;
			memberTitle.BackColor = UiKit.Card;
			leftLayout.Controls.Add(memberTitle, 0, 0);
			memberTitle.Controls.Add(new Label
			{
				Text = "在线成员",
				Font = UiKit.SubTitle,
				ForeColor = UiKit.TextColor,
				AutoSize = true,
				Location = new Point(0, 4)
			});
			FlowLayoutPanel memberTitleRight = new FlowLayoutPanel();
			memberTitleRight.Dock = DockStyle.Right;
			memberTitleRight.Width = 110;
			memberTitleRight.FlowDirection = FlowDirection.RightToLeft;
			memberTitleRight.WrapContents = false;
			memberTitleRight.BackColor = UiKit.Card;
			memberTitle.Controls.Add(memberTitleRight);
			btnScan = UiKit.SecondaryButton("重新扫描");
			btnScan.Width = 96;
			btnScan.Height = 30;
			btnScan.Margin = new Padding(0);
			memberTitleRight.Controls.Add(btnScan);

			peers = new ListView();
			peers.Dock = DockStyle.Fill;
			peers.View = View.Details;
			peers.MultiSelect = adminMode;
			UiKit.StyleList(peers);
			peers.Columns.Add("名字", 170);
			peers.Columns.Add("IP", 100);
			leftLayout.Controls.Add(peers, 0, 1);

			FlowLayoutPanel muteRow = new FlowLayoutPanel();
			muteRow.Dock = DockStyle.Fill;
			muteRow.FlowDirection = FlowDirection.LeftToRight;
			muteRow.WrapContents = false;
			muteRow.BackColor = UiKit.Card;
			muteRow.Padding = new Padding(0, 6, 0, 0);
			leftLayout.Controls.Add(muteRow, 0, 2);
			btnMute = UiKit.SecondaryButton("禁言 / 解禁");
			btnMute.Width = 120;
			btnMute.Visible = adminMode;
			muteRow.Controls.Add(btnMute);

			FlowLayoutPanel nameRow = new FlowLayoutPanel();
			nameRow.Dock = DockStyle.Fill;
			nameRow.FlowDirection = FlowDirection.LeftToRight;
			nameRow.WrapContents = false;
			nameRow.BackColor = UiKit.Card;
			nameRow.Padding = new Padding(0, 6, 0, 0);
			leftLayout.Controls.Add(nameRow, 0, 3);
			tbMyName = new TextBox();
			tbMyName.Width = 200;
			tbMyName.BorderStyle = BorderStyle.FixedSingle;
			tbMyName.Margin = new Padding(0, 0, 8, 0);
			nameRow.Controls.Add(tbMyName);
			btnSaveName = UiKit.SecondaryButton("保存");
			btnSaveName.Width = 88;
			nameRow.Controls.Add(btnSaveName);
			UiKit.SetPlaceholder(tbMyName, "我的名称");

			Panel rightCard = UiKit.CardPanel();
			rightCard.Dock = DockStyle.Fill;
			rightCard.Padding = new Padding(16, 12, 16, 12);
			split.Controls.Add(rightCard, 1, 0);

			TableLayoutPanel rightLayout = new TableLayoutPanel();
			rightLayout.Dock = DockStyle.Fill;
			rightLayout.ColumnCount = 1;
			rightLayout.RowCount = 3;
			rightLayout.BackColor = UiKit.Card;
			rightLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			rightLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48f));
			rightLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40f));
			rightCard.Controls.Add(rightLayout);

			logBox = new TextBox();
			logBox.Dock = DockStyle.Fill;
			logBox.Multiline = true;
			logBox.ReadOnly = true;
			logBox.ScrollBars = ScrollBars.Vertical;
			logBox.BackColor = Color.FromArgb(250, 251, 253);
			logBox.BorderStyle = BorderStyle.FixedSingle;
			logBox.Font = UiKit.Body;
			logBox.Margin = new Padding(0, 0, 0, 8);
			rightLayout.Controls.Add(logBox, 0, 0);

			TableLayoutPanel inputRow = new TableLayoutPanel();
			inputRow.Dock = DockStyle.Fill;
			inputRow.ColumnCount = 2;
			inputRow.RowCount = 1;
			inputRow.BackColor = UiKit.Card;
			inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
			inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 96f));
			inputRow.Margin = new Padding(0, 0, 0, 4);
			rightLayout.Controls.Add(inputRow, 0, 1);

			tbInput = new TextBox();
			tbInput.Dock = DockStyle.Fill;
			tbInput.Font = new Font("Microsoft YaHei UI", 10f);
			tbInput.BorderStyle = BorderStyle.FixedSingle;
			tbInput.Margin = new Padding(0, 4, 8, 0);
			inputRow.Controls.Add(tbInput, 0, 0);
			UiKit.SetPlaceholder(tbInput, "输入消息，回车发送");
			btnSend = UiKit.PrimaryButton("发送");
			btnSend.Dock = DockStyle.Fill;
			btnSend.Margin = new Padding(0, 2, 0, 0);
			inputRow.Controls.Add(btnSend, 1, 0);

			FlowLayoutPanel bottomRow = new FlowLayoutPanel();
			bottomRow.Dock = DockStyle.Fill;
			bottomRow.FlowDirection = FlowDirection.LeftToRight;
			bottomRow.WrapContents = false;
			bottomRow.BackColor = UiKit.Card;
			rightLayout.Controls.Add(bottomRow, 0, 2);
			btnClear = UiKit.SecondaryButton("清屏");
			btnClear.Width = 80;
			bottomRow.Controls.Add(btnClear);
			Button btnClearHistory = UiKit.SecondaryButton("清空历史");
			btnClearHistory.Width = 96;
			bottomRow.Controls.Add(btnClearHistory);

			Panel status = UiKit.StatusBar(lblStatus = new Label());
			root.Controls.Add(status, 0, 2);

			btnScan.Click += delegate
			{
				Scan();
			};
			btnMute.Click += delegate
			{
				ToggleMuteSelected();
			};
			btnSend.Click += delegate
			{
				SendMessage();
			};
			btnClear.Click += delegate
			{
				logBox.Clear();
			};
			btnClearHistory.Click += delegate
			{
				ClearHistory();
			};
			btnSaveName.Click += delegate
			{
				SaveName();
			};
			tbMyName.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter)
				{
					e.SuppressKeyPress = true;
					SaveName();
				}
			};
			tbInput.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter && !e.Shift)
				{
					e.SuppressKeyPress = true;
					SendMessage();
				}
			};
			peers.SelectedIndexChanged += delegate
			{
				UpdateMuteButton();
			};
			UpdateMuteButton();
			ResumeLayout();
		}

		private void UpdateMuteButton()
		{
			if (btnMute != null && btnMute.Visible)
			{
				btnMute.Enabled = peers != null && peers.SelectedItems.Count > 0;
			}
		}

		private void ClearHistory()
		{
			if (MessageBox.Show(this, "将删除本机保存的聊天记录，其他电脑上的记录不受影响。\r\n联网时仍可能从其他电脑补回历史。是否继续？", "清空聊天历史", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
			{
				return;
			}
			FileTransferService.ClearChatLog();
			logBox.Clear();
			historyKeys.Clear();
			historySynced = true;
			lblStatus.Text = "本机聊天历史已清空。";
		}
	}
	// 控制端「一体窗口」：上半部分是文件传输，下半部分是局域网群聊，同一个页面里上下排列。
	// 只给控制端用；客户端的两个窗口保持原样。
	internal class HubForm : Form
	{
		private static HubForm shared;

		private NetGateServer server;

		private AdminConfig cfg;

		private ListView peers;

		private Button btnScan;

		private Button btnSend;

		private Button btnOpenDir;

		private Button btnAddIp;

		private Button btnMute;

		private Button btnChatSend;

		private Button btnClear;

		private Button btnSaveName;

		private TextBox tbIp;

		private TextBox tbInput;

		private TextBox tbMyName;

		private TextBox logBox;

		private TextBox transferLog;

		private TabControl tabs;

		private ProgressBar progress;

		private Label lblFile;

		private Label lblStatus;

		private Label lblMine;

		private System.Windows.Forms.Timer refresh;

		private bool scanning;

		private bool sending;

		private bool historySynced;

		private readonly HashSet<string> logKeys = new HashSet<string>(StringComparer.Ordinal);

		private HubForm(NetGateServer server, AdminConfig cfg)
		{
			this.server = server;
			this.cfg = cfg;
			Text = "NetGate 局域网（文件传输 / 群聊）";
			base.Size = new Size(940, 800);
			base.MinimumSize = new Size(880, 720);
			base.StartPosition = FormStartPosition.CenterParent;
			Font = new Font("Microsoft YaHei UI", 9f);
			base.AutoScaleMode = AutoScaleMode.None;
			base.Icon = NetGateIcon.Create();
			BuildUiModern();
			UiKit.AddBetaWatermark(this);
			base.Load += delegate
			{
				FileTransferService.EnsureStarted();
				FileTransferService.ChatArrived += OnChatArrived;
				FileTransferService.SetMutedIps((server == null) ? "" : server.MutedIps());
				UpdateMine();
				ShowHistory(FileTransferService.LoadChatLog(300));
				Scan();
				refresh = new System.Windows.Forms.Timer
				{
					Interval = 8000
				};
				refresh.Tick += delegate
				{
					FileTransferService.SetMutedIps((server == null) ? "" : server.MutedIps());
					if (!scanning)
					{
						Scan();
					}
				};
				refresh.Start();
			};
			base.FormClosed += delegate
			{
				try
				{
					if (refresh != null)
					{
						refresh.Stop();
						refresh.Dispose();
					}
				}
				catch
				{
				}
				try
				{
					FileTransferService.ChatArrived -= OnChatArrived;
				}
				catch
				{
				}
				shared = null;
			};
		}

		public static void ShowShared(IWin32Window owner, NetGateServer server, AdminConfig cfg, int tab)
		{
			if (shared == null || shared.IsDisposed)
			{
				shared = new HubForm(server, cfg);
			}
			shared.Show(owner);
			shared.SelectTab(tab);
			shared.Activate();
		}

		private void SelectTab(int tab)
		{
			if (tabs == null || tabs.TabPages.Count < 2)
			{
				return;
			}
			tabs.SelectedIndex = ((tab == 0) ? 1 : 0);
		}

		private void BuildUi()
		{
			Panel panel = new Panel();
			panel.Dock = DockStyle.Top;
			panel.Height = 50;
			panel.BackColor = Color.FromArgb(15, 23, 42);
			base.Controls.Add(panel);
			panel.Controls.Add(new Label
			{
				Text = "局域网（文件传输 / 群聊）",
				ForeColor = Color.White,
				Font = new Font("Microsoft YaHei UI", 14f, FontStyle.Bold),
				Location = new Point(16, 8),
				AutoSize = true
			});
			lblMine = new Label
			{
				ForeColor = Color.FromArgb(148, 163, 184),
				Location = new Point(300, 15),
				AutoSize = true
			};
			panel.Controls.Add(lblMine);

			base.Controls.Add(new Label
			{
				Text = "① 文件传输",
				Font = new Font("Microsoft YaHei UI", 10f, FontStyle.Bold),
				Location = new Point(16, 58),
				AutoSize = true
			});
			base.Controls.Add(new Label
			{
				Text = "局域网内装有 NetGate 的电脑（可多选）",
				Location = new Point(16, 82),
				AutoSize = true
			});
			peers = new ListView
			{
				Location = new Point(16, 104),
				Size = new Size(460, 150),
				View = View.Details,
				FullRowSelect = true,
				HideSelection = false,
				MultiSelect = true
			};
			peers.Columns.Add("电脑", 280);
			peers.Columns.Add("IP 地址", 120);
			base.Controls.Add(peers);

			btnScan = new Button
			{
				Text = "重新扫描",
				Location = new Point(492, 104),
				Size = new Size(120, 32)
			};
			base.Controls.Add(btnScan);
			btnSend = new Button
			{
				Text = "发送文件…（可多选）",
				Location = new Point(620, 104),
				Size = new Size(176, 32),
				BackColor = Color.FromArgb(37, 99, 235),
				ForeColor = Color.White,
				FlatStyle = FlatStyle.Flat
			};
			btnSend.FlatAppearance.BorderSize = 0;
			base.Controls.Add(btnSend);
			btnOpenDir = new Button
			{
				Text = "接收文件夹",
				Location = new Point(804, 104),
				Size = new Size(100, 32)
			};
			base.Controls.Add(btnOpenDir);

			base.Controls.Add(new Label
			{
				Text = "扫不到时手动填对方 IP：",
				Location = new Point(492, 146),
				AutoSize = true,
				ForeColor = Color.FromArgb(71, 85, 105)
			});
			tbIp = new TextBox
			{
				Location = new Point(492, 168),
				Size = new Size(120, 25)
			};
			base.Controls.Add(tbIp);
			btnAddIp = new Button
			{
				Text = "添加",
				Location = new Point(620, 167),
				Size = new Size(70, 27)
			};
			base.Controls.Add(btnAddIp);

			progress = new ProgressBar
			{
				Location = new Point(492, 204),
				Size = new Size(412, 16),
				Maximum = 1000
			};
			base.Controls.Add(progress);
			lblFile = new Label
			{
				Location = new Point(492, 224),
				Size = new Size(412, 30),
				ForeColor = Color.FromArgb(71, 85, 105)
			};
			base.Controls.Add(lblFile);

			base.Controls.Add(new Label
			{
				Text = "② 局域网群聊",
				Font = new Font("Microsoft YaHei UI", 10f, FontStyle.Bold),
				Location = new Point(16, 268),
				AutoSize = true
			});
			logBox = new TextBox
			{
				Location = new Point(16, 292),
				Size = new Size(888, 300),
				Multiline = true,
				ReadOnly = true,
				ScrollBars = ScrollBars.Vertical,
				BackColor = Color.FromArgb(248, 250, 252),
				Font = new Font("Microsoft YaHei UI", 10f)
			};
			base.Controls.Add(logBox);
			tbInput = new TextBox
			{
				Location = new Point(16, 602),
				Size = new Size(770, 28),
				Font = new Font("Microsoft YaHei UI", 10f)
			};
			base.Controls.Add(tbInput);
			btnChatSend = new Button
			{
				Text = "群发",
				Location = new Point(794, 600),
				Size = new Size(110, 32),
				BackColor = Color.FromArgb(37, 99, 235),
				ForeColor = Color.White,
				FlatStyle = FlatStyle.Flat
			};
			btnChatSend.FlatAppearance.BorderSize = 0;
			base.Controls.Add(btnChatSend);

			btnMute = new Button
			{
				Text = "禁言/解禁",
				Location = new Point(16, 644),
				Size = new Size(110, 30)
			};
			base.Controls.Add(btnMute);
			btnClear = new Button
			{
				Text = "清屏",
				Location = new Point(134, 644),
				Size = new Size(70, 30)
			};
			base.Controls.Add(btnClear);
			base.Controls.Add(new Label
			{
				Text = "我的名称：",
				Location = new Point(220, 651),
				AutoSize = true
			});
			tbMyName = new TextBox
			{
				Location = new Point(288, 646),
				Size = new Size(160, 26)
			};
			base.Controls.Add(tbMyName);
			btnSaveName = new Button
			{
				Text = "保存",
				Location = new Point(456, 645),
				Size = new Size(70, 28)
			};
			base.Controls.Add(btnSaveName);

			lblStatus = new Label
			{
				Location = new Point(16, 690),
				Size = new Size(888, 60),
				ForeColor = Color.FromArgb(71, 85, 105)
			};
			base.Controls.Add(lblStatus);

			btnScan.Click += delegate
			{
				Scan();
			};
			btnSend.Click += delegate
			{
				SendFiles();
			};
			btnOpenDir.Click += delegate
			{
				try
				{
					string text = FileTransferService.Current.ReceiveDir;
					if (string.IsNullOrEmpty(text))
					{
						text = Path.Combine(Program.DataDir, "Received");
					}
					Directory.CreateDirectory(text);
					Process.Start("explorer.exe", "\"" + text + "\"");
				}
				catch (Exception ex)
				{
					MessageBox.Show(this, "打不开接收文件夹：" + ex.Message, "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				}
			};
			btnAddIp.Click += delegate
			{
				AddManualIp();
			};
			btnMute.Click += delegate
			{
				ToggleMuteSelected();
			};
			btnChatSend.Click += delegate
			{
				SendMessage();
			};
			btnClear.Click += delegate
			{
				logBox.Clear();
				logKeys.Clear();
			};
			btnSaveName.Click += delegate
			{
				SaveName();
			};
			tbMyName.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter)
				{
					e.SuppressKeyPress = true;
					SaveName();
				}
			};
			tbInput.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter && !e.Shift)
				{
					e.SuppressKeyPress = true;
					SendMessage();
				}
			};
		}

		private void UpdateMine()
		{
			FileTransferService current = FileTransferService.Current;
			lblMine.Text = "我的名称：" + current.LocalName + "    IP：" + Util.LanIPv4();
			if (!tbMyName.Focused)
			{
				tbMyName.Text = current.LocalName;
			}
		}

		private void SaveName()
		{
			string text = tbMyName.Text.Trim();
			if (text.Length == 0)
			{
				MessageBox.Show(this, "名称不能为空。", "NetGate 局域网", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			FileTransferService.Current.SetLocalName(text);
			UpdateMine();
			lblStatus.Text = "名称已保存：" + text;
		}

		// ---------- 文件传输 ----------

		private void Scan()
		{
			if (scanning)
			{
				return;
			}
			scanning = true;
			btnScan.Enabled = false;
			List<string> selectedIds = new List<string>();
			foreach (ListViewItem item in peers.SelectedItems)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && !selectedIds.Contains(transferPeer.Id))
				{
					selectedIds.Add(transferPeer.Id);
				}
			}
			Thread thread = new Thread((ThreadStart)delegate
			{
				List<TransferPeer> list = FileTransferService.Current.Discover(2500);
				SafeInvoke(delegate
				{
					scanning = false;
					btnScan.Enabled = true;
					peers.BeginUpdate();
					peers.Items.Clear();
					foreach (TransferPeer item2 in list)
					{
						AddPeer(item2);
					}
					peers.EndUpdate();
					foreach (ListViewItem item3 in peers.Items)
					{
						TransferPeer transferPeer2 = item3.Tag as TransferPeer;
						if (transferPeer2 != null && selectedIds.Contains(transferPeer2.Id))
						{
							item3.Selected = true;
						}
					}
					lblStatus.Text = ((list.Count == 0) ? "没有发现其它 NetGate 电脑。请确认对方也开着本软件；仍找不到时可用右侧“手动填对方 IP”。" : ("发现 " + list.Count + " 台电脑。选中后点“发送文件…”，可多选。"));
					SyncHistory(list);
					UpdateActionButtons();
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private void AddPeer(TransferPeer peer)
		{
			if (peer == null || HasPeer(peer.Id))
			{
				return;
			}
			ListViewItem listViewItem = new ListViewItem(PeerLabel(peer));
			listViewItem.SubItems.Add(peer.Ip);
			listViewItem.Tag = peer;
			peers.Items.Add(listViewItem);
		}

		private bool HasPeer(string id)
		{
			foreach (ListViewItem item in peers.Items)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && transferPeer.Id == id)
				{
					return true;
				}
			}
			return false;
		}

		private string PeerLabel(TransferPeer peer)
		{
			string text = string.IsNullOrEmpty(peer.Name) ? peer.Ip : peer.Name;
			if (IsPeerMuted(peer))
			{
				text += "（已禁言）";
			}
			return text;
		}

		private void RefreshPeerLabels()
		{
			foreach (ListViewItem item in peers.Items)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null)
				{
					item.Text = PeerLabel(transferPeer);
				}
			}
		}

		private List<TransferPeer> SelectedPeers()
		{
			List<TransferPeer> list = new List<TransferPeer>();
			foreach (ListViewItem item in peers.SelectedItems)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && transferPeer.Id != FileTransferService.Current.LocalId && !list.Exists((TransferPeer x) => x.Id == transferPeer.Id))
				{
					list.Add(transferPeer);
				}
			}
			return list;
		}

		private void AddManualIp()
		{
			string text = tbIp.Text.Trim();
			if (text.Length == 0)
			{
				MessageBox.Show(this, "请先填写对方 IP，例如 192.168.109.38。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			lblStatus.Text = "正在探测 " + text + " …";
			Thread thread = new Thread((ThreadStart)delegate
			{
				TransferPeer transferPeer = FileTransferService.Current.ProbePeer(text, 1500);
				SafeInvoke(delegate
				{
					if (transferPeer == null)
					{
						lblStatus.Text = "探测失败：" + text + "（确认对方开着本软件、防火墙已放行）";
						return;
					}
					AddPeer(transferPeer);
					UpdateActionButtons();
					lblStatus.Text = "已添加：" + PeerLabel(transferPeer) + "（" + transferPeer.Ip + "）";
					tbIp.Clear();
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private void SendFiles()
		{
			if (sending)
			{
				return;
			}
			List<TransferPeer> list = SelectedPeers();
			if (list.Count == 0)
			{
				MessageBox.Show(this, "请先在上面的列表里选中接收方电脑（可按住 Ctrl / Shift 多选）。", "NetGate 文件传输", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			using (OpenFileDialog openFileDialog = new OpenFileDialog())
			{
				openFileDialog.Title = ((list.Count == 1) ? ("选择要发送给 " + list[0].Display + " 的文件") : ("选择要发送给 " + list.Count + " 台电脑的文件"));
				openFileDialog.Multiselect = true;
				openFileDialog.Filter = "所有文件 (*.*)|*.*";
				if (openFileDialog.ShowDialog(this) != DialogResult.OK)
				{
					return;
				}
				string[] files = openFileDialog.FileNames;
				sending = true;
				btnSend.Enabled = false;
				lblFile.Text = ((list.Count == 1) ? "正在等待对方接收…" : ("正在发送到 " + list.Count + " 台电脑…"));
				Action<long, long, string> progressCb = null;
				if (list.Count == 1)
				{
					progressCb = delegate(long done, long total, string name)
					{
						ShowProgress(done, total, name);
					};
				}
				Thread thread = new Thread((ThreadStart)delegate
				{
					int ok = 0;
					int fail = 0;
					List<string> errors = new List<string>();
					object gate = new object();
					List<Thread> threads = new List<Thread>();
					foreach (TransferPeer item in list)
					{
						TransferPeer p = item;
						Thread thread2 = new Thread((ThreadStart)delegate
						{
							string error;
							string text = FileTransferService.Current.Send(p, files, progressCb, out error);
							lock (gate)
							{
								if (text != null)
								{
									ok++;
								}
								else
								{
									fail++;
									errors.Add(p.Display + "：" + error);
								}
							}
						});
						thread2.IsBackground = true;
						thread2.Start();
						threads.Add(thread2);
					}
					foreach (Thread item2 in threads)
					{
						item2.Join(180000);
					}
					SafeInvoke(delegate
					{
						sending = false;
						UpdateActionButtons();
						if (fail == 0)
						{
							progress.Value = 1000;
							lblFile.Text = ((list.Count == 1) ? "发送完成。" : ("已发送给 " + ok + " 台电脑。"));
						}
						else
						{
							progress.Value = 0;
							lblFile.Text = "发送完成：成功 " + ok + " 台，失败 " + fail + " 台（" + string.Join("；", errors.ToArray()) + "）";
						}
					});
				});
				thread.IsBackground = true;
				thread.Start();
			}
		}

		private void ShowProgress(long done, long total, string name)
		{
			if (base.IsDisposed)
			{
				return;
			}
			SafeInvoke(delegate
			{
				progress.Value = (int)((total > 0) ? Math.Min(1000L, done * 1000 / total) : 0);
				lblFile.Text = "正在传输：" + name + "  " + Util.FmtBytes(done) + " / " + Util.FmtBytes(total);
			});
		}

		// ---------- 局域网群聊 ----------

		private void SendMessage()
		{
			if (sending)
			{
				return;
			}
			string text = tbInput.Text.Trim();
			if (text.Length == 0)
			{
				tbInput.Focus();
				return;
			}
			List<TransferPeer> list = new List<TransferPeer>();
			foreach (ListViewItem item in peers.Items)
			{
				TransferPeer transferPeer = item.Tag as TransferPeer;
				if (transferPeer != null && transferPeer.Id != FileTransferService.Current.LocalId)
				{
					list.Add(transferPeer);
				}
			}
			sending = true;
			btnChatSend.Enabled = false;
			tbInput.Clear();
			DateTime at = DateTime.Now;
			ChatMessage chatMessage = new ChatMessage();
			chatMessage.At = at;
			chatMessage.FromName = FileTransferService.Current.LocalName;
			chatMessage.Text = text;
			AppendChat(chatMessage, false);
			lblStatus.Text = "正在群发…";
			Thread thread = new Thread((ThreadStart)delegate
			{
				int failed;
				int num = FileTransferService.Current.SendChatAll(text, list, at, out failed);
				if (num > 0)
				{
					FileTransferService.AppendChatLog(FileTransferService.Current.LocalName, at, text);
				}
				SafeInvoke(delegate
				{
					sending = false;
					btnChatSend.Enabled = true;
					lblStatus.Text = ((num > 0) ? ("已群发给 " + num + " 台电脑" + ((failed > 0) ? ("（" + failed + " 台未送达）") : "")) : "群发失败：没有可送达的电脑。");
					if (num == 0)
					{
						Scan();
					}
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private void OnChatArrived(ChatMessage m)
		{
			try
			{
				if (base.IsDisposed)
				{
					return;
				}
				SafeInvoke(delegate
				{
					AppendChat(m, true);
					lblStatus.Text = "收到 " + m.FromName + " 的群聊消息";
				});
			}
			catch
			{
			}
		}

		private void AppendChat(ChatMessage m, bool checkDup)
		{
			string text = ChatKey(m);
			if (checkDup && logKeys.Contains(text))
			{
				return;
			}
			logKeys.Add(text);
			if (logBox.TextLength > 40000)
			{
				logBox.Clear();
			}
			logBox.AppendText(FormatLine(m) + "\r\n");
			logBox.SelectionStart = logBox.TextLength;
			logBox.ScrollToCaret();
		}

		private void ShowHistory(List<ChatMessage> list)
		{
			if (list == null || list.Count == 0)
			{
				return;
			}
			list.Sort((ChatMessage a, ChatMessage b) => a.At.CompareTo(b.At));
			foreach (ChatMessage item in list)
			{
				AppendChat(item, true);
			}
		}

		// 向在线成员补拉历史：新加入的电脑也能看到别人保存的群聊记录。
		private void SyncHistory(List<TransferPeer> memberList)
		{
			if (historySynced || memberList == null || memberList.Count == 0)
			{
				return;
			}
			historySynced = true;
			List<TransferPeer> targets = new List<TransferPeer>();
			foreach (TransferPeer peer in memberList)
			{
				if (peer != null && peer.Id != FileTransferService.Current.LocalId)
				{
					targets.Add(peer);
				}
				if (targets.Count >= 6)
				{
					break;
				}
			}
			if (targets.Count == 0)
			{
				return;
			}
			Thread thread = new Thread((ThreadStart)delegate
			{
				List<ChatMessage> fetched = new List<ChatMessage>();
				foreach (TransferPeer peer in targets)
				{
					foreach (ChatMessage message in FileTransferService.Current.FetchHistory(peer, 60))
					{
						fetched.Add(message);
					}
				}
				if (fetched.Count == 0)
				{
					return;
				}
				SafeInvoke(delegate
				{
					HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
					foreach (string key in logKeys)
					{
						seen.Add(key);
					}
					List<ChatMessage> added = new List<ChatMessage>();
					foreach (ChatMessage message in fetched)
					{
						string key = ChatKey(message);
						if (seen.Add(key))
						{
							added.Add(message);
						}
					}
					if (added.Count == 0)
					{
						return;
					}
					added.Sort(delegate(ChatMessage a, ChatMessage b)
					{
						return a.At.CompareTo(b.At);
					});
					StringBuilder builder = new StringBuilder();
					foreach (ChatMessage message in added)
					{
						builder.Append(FormatLine(message)).Append("\r\n");
						logKeys.Add(ChatKey(message));
						FileTransferService.AppendChatLog(message.FromName, message.At, message.Text);
					}
					logBox.Text = builder.ToString() + logBox.Text;
					logBox.SelectionStart = logBox.TextLength;
					logBox.ScrollToCaret();
					lblStatus.Text = "已补上 " + added.Count + " 条历史记录。";
				});
			});
			thread.IsBackground = true;
			thread.Start();
		}

		private static string ChatKey(ChatMessage m)
		{
			return m.At.ToString("yyyy-MM-dd HH:mm:ss") + "|" + m.FromName + "|" + m.Text;
		}

		private static string FormatLine(ChatMessage m)
		{
			string text = ((m.FromName == FileTransferService.Current.LocalName) ? "我" : m.FromName);
			string text2 = (string.IsNullOrEmpty(m.FromIp) ? "" : ("（" + m.FromIp + "）"));
			return "[" + m.At.ToString("HH:mm:ss") + "] " + text + text2 + "：" + m.Text;
		}

		// ---------- 禁言 ----------

		private bool IsPeerMuted(TransferPeer peer)
		{
			if (server == null || peer == null)
			{
				return false;
			}
			Device device = server.FindByIp(peer.Ip);
			if (device == null)
			{
				return false;
			}
			lock (device.Sync)
			{
				return device.ChatMuted;
			}
		}

		private void ToggleMuteSelected()
		{
			List<TransferPeer> list = SelectedPeers();
			if (list.Count == 0)
			{
				MessageBox.Show(this, "请先在上面的列表里选中电脑（可多选），再点“禁言/解禁”。", "NetGate 群聊", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				return;
			}
			bool flag = false;
			foreach (TransferPeer item in list)
			{
				Device device = server.FindByIp(item.Ip);
				if (device != null)
				{
					lock (device.Sync)
					{
						if (!device.ChatMuted)
						{
							flag = true;
						}
					}
				}
			}
			int num = 0;
			foreach (TransferPeer item2 in list)
			{
				Device device2 = server.FindByIp(item2.Ip);
				if (device2 == null)
				{
					continue;
				}
				server.SetChatMuted(device2.Mac, flag);
				if (cfg != null)
				{
					if (flag)
					{
						cfg.Muted[device2.Mac] = true;
					}
					else
					{
						cfg.Muted.Remove(device2.Mac);
					}
				}
				num++;
			}
			if (cfg != null)
			{
				cfg.Save();
			}
			FileTransferService.SetMutedIps(server.MutedIps());
			RefreshPeerLabels();
			lblStatus.Text = (flag ? "已禁言 " : "已解除禁言 ") + num + " 台电脑（控制端不再显示它们的群聊消息）。";
		}

		private void SafeInvoke(MethodInvoker action)
		{
			try
			{
				if (base.IsDisposed || !base.IsHandleCreated)
				{
					return;
				}
				if (base.InvokeRequired)
				{
					BeginInvoke(action);
				}
				else
				{
					action();
				}
			}
			catch
			{
			}
		}

		private void BuildUiModern()
		{
			SuspendLayout();
			UiKit.Apply(this);
			DoubleBuffered = true;
			Text = "NetGate 局域网";
			base.Size = new Size(1020, 780);
			MinimumSize = new Size(940, 680);

			TableLayoutPanel root = new TableLayoutPanel();
			root.Dock = DockStyle.Fill;
			root.ColumnCount = 1;
			root.RowCount = 3;
			root.BackColor = UiKit.Bg;
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64f));
			root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
			base.Controls.Add(root);

			Panel header = new Panel();
			header.Dock = DockStyle.Fill;
			header.BackColor = UiKit.Header;
			root.Controls.Add(header, 0, 0);
			header.Controls.Add(new Label
			{
				Text = "NetGate 局域网",
				ForeColor = Color.White,
				Font = UiKit.Title,
				AutoSize = true,
				Location = new Point(20, 18)
			});
			FlowLayoutPanel headerRight = new FlowLayoutPanel();
			headerRight.Dock = DockStyle.Right;
			headerRight.Width = 560;
			headerRight.FlowDirection = FlowDirection.RightToLeft;
			headerRight.WrapContents = false;
			headerRight.BackColor = UiKit.Header;
			headerRight.Padding = new Padding(0, 22, 20, 0);
			header.Controls.Add(headerRight);
			lblMine = new Label();
			lblMine.ForeColor = UiKit.HeaderText;
			lblMine.Font = UiKit.Body;
			lblMine.AutoSize = true;
			lblMine.Margin = new Padding(0);
			headerRight.Controls.Add(lblMine);

			Panel body = new Panel();
			body.Dock = DockStyle.Fill;
			body.BackColor = UiKit.Bg;
			body.Padding = new Padding(16, 16, 16, 12);
			root.Controls.Add(body, 0, 1);

			TableLayoutPanel split = new TableLayoutPanel();
			split.Dock = DockStyle.Fill;
			split.ColumnCount = 2;
			split.RowCount = 1;
			split.BackColor = UiKit.Bg;
			split.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 360f));
			split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
			body.Controls.Add(split);

			Panel leftCard = UiKit.CardPanel();
			leftCard.Dock = DockStyle.Fill;
			leftCard.Margin = new Padding(0, 0, 12, 0);
			leftCard.Padding = new Padding(16, 12, 16, 12);
			split.Controls.Add(leftCard, 0, 0);

			TableLayoutPanel leftLayout = new TableLayoutPanel();
			leftLayout.Dock = DockStyle.Fill;
			leftLayout.ColumnCount = 1;
			leftLayout.RowCount = 5;
			leftLayout.BackColor = UiKit.Card;
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34f));
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42f));
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42f));
			leftLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
			leftCard.Controls.Add(leftLayout);

			Panel memberTitle = new Panel();
			memberTitle.Dock = DockStyle.Fill;
			memberTitle.BackColor = UiKit.Card;
			leftLayout.Controls.Add(memberTitle, 0, 0);
			memberTitle.Controls.Add(new Label
			{
				Text = "局域网成员",
				Font = UiKit.SubTitle,
				ForeColor = UiKit.TextColor,
				AutoSize = true,
				Location = new Point(0, 4)
			});
			FlowLayoutPanel memberTitleRight = new FlowLayoutPanel();
			memberTitleRight.Dock = DockStyle.Right;
			memberTitleRight.Width = 110;
			memberTitleRight.FlowDirection = FlowDirection.RightToLeft;
			memberTitleRight.WrapContents = false;
			memberTitleRight.BackColor = UiKit.Card;
			memberTitle.Controls.Add(memberTitleRight);
			btnScan = UiKit.SecondaryButton("重新扫描");
			btnScan.Width = 96;
			btnScan.Height = 30;
			btnScan.Margin = new Padding(0);
			memberTitleRight.Controls.Add(btnScan);

			peers = new ListView();
			peers.Dock = DockStyle.Fill;
			peers.View = View.Details;
			peers.MultiSelect = true;
			UiKit.StyleList(peers);
			peers.Columns.Add("电脑", 220);
			peers.Columns.Add("IP 地址", 100);
			leftLayout.Controls.Add(peers, 0, 1);

			FlowLayoutPanel manualRow = new FlowLayoutPanel();
			manualRow.Dock = DockStyle.Fill;
			manualRow.FlowDirection = FlowDirection.LeftToRight;
			manualRow.WrapContents = false;
			manualRow.BackColor = UiKit.Card;
			manualRow.Padding = new Padding(0, 6, 0, 0);
			leftLayout.Controls.Add(manualRow, 0, 2);
			tbIp = new TextBox();
			tbIp.Width = 200;
			tbIp.BorderStyle = BorderStyle.FixedSingle;
			tbIp.Margin = new Padding(0, 0, 8, 0);
			UiKit.SetPlaceholder(tbIp, "对方 IP 地址");
			manualRow.Controls.Add(tbIp);
			btnAddIp = UiKit.SecondaryButton("添加");
			btnAddIp.Width = 74;
			manualRow.Controls.Add(btnAddIp);

			FlowLayoutPanel memberActions = new FlowLayoutPanel();
			memberActions.Dock = DockStyle.Fill;
			memberActions.FlowDirection = FlowDirection.LeftToRight;
			memberActions.WrapContents = false;
			memberActions.BackColor = UiKit.Card;
			memberActions.Padding = new Padding(0, 6, 0, 0);
			leftLayout.Controls.Add(memberActions, 0, 3);
			btnMute = UiKit.SecondaryButton("禁言 / 解禁");
			btnMute.Width = 120;
			btnMute.Visible = (server != null);
			memberActions.Controls.Add(btnMute);

			FlowLayoutPanel nameRow = new FlowLayoutPanel();
			nameRow.Dock = DockStyle.Fill;
			nameRow.FlowDirection = FlowDirection.LeftToRight;
			nameRow.WrapContents = false;
			nameRow.BackColor = UiKit.Card;
			nameRow.Padding = new Padding(0, 6, 0, 0);
			leftLayout.Controls.Add(nameRow, 0, 4);
			tbMyName = new TextBox();
			tbMyName.Width = 200;
			tbMyName.BorderStyle = BorderStyle.FixedSingle;
			tbMyName.Margin = new Padding(0, 0, 8, 0);
			UiKit.SetPlaceholder(tbMyName, "我的名称");
			nameRow.Controls.Add(tbMyName);
			btnSaveName = UiKit.SecondaryButton("保存");
			btnSaveName.Width = 74;
			nameRow.Controls.Add(btnSaveName);

			tabs = new TabControl();
			tabs.Dock = DockStyle.Fill;
			tabs.Font = UiKit.Body;
			tabs.Padding = new Point(16, 6);
			split.Controls.Add(tabs, 1, 0);

			TabPage filePage = new TabPage();
			filePage.Text = "文件传输";
			filePage.BackColor = UiKit.Card;
			filePage.Padding = new Padding(16);
			tabs.TabPages.Add(filePage);

			TabPage chatPage = new TabPage();
			chatPage.Text = "群聊";
			chatPage.BackColor = UiKit.Card;
			chatPage.Padding = new Padding(16);
			tabs.TabPages.Add(chatPage);

			TableLayoutPanel fileLayout = new TableLayoutPanel();
			fileLayout.Dock = DockStyle.Fill;
			fileLayout.ColumnCount = 1;
			fileLayout.RowCount = 4;
			fileLayout.BackColor = UiKit.Card;
			fileLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52f));
			fileLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			fileLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 22f));
			fileLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28f));
			filePage.Controls.Add(fileLayout);

			FlowLayoutPanel fileToolbar = new FlowLayoutPanel();
			fileToolbar.Dock = DockStyle.Fill;
			fileToolbar.FlowDirection = FlowDirection.LeftToRight;
			fileToolbar.WrapContents = false;
			fileToolbar.BackColor = UiKit.Card;
			fileLayout.Controls.Add(fileToolbar, 0, 0);
			btnSend = UiKit.PrimaryButton("发送文件…");
			btnSend.Width = 130;
			fileToolbar.Controls.Add(btnSend);
			btnOpenDir = UiKit.SecondaryButton("打开接收文件夹");
			btnOpenDir.Width = 132;
			fileToolbar.Controls.Add(btnOpenDir);

			transferLog = new TextBox();
			transferLog.Dock = DockStyle.Fill;
			transferLog.Multiline = true;
			transferLog.ReadOnly = true;
			transferLog.ScrollBars = ScrollBars.Vertical;
			transferLog.BackColor = Color.FromArgb(250, 251, 253);
			transferLog.BorderStyle = BorderStyle.FixedSingle;
			transferLog.Font = UiKit.Mono;
			transferLog.Margin = new Padding(0, 4, 0, 8);
			fileLayout.Controls.Add(transferLog, 0, 1);

			progress = new ProgressBar();
			progress.Dock = DockStyle.Fill;
			progress.Maximum = 1000;
			progress.Margin = new Padding(0, 0, 0, 4);
			fileLayout.Controls.Add(progress, 0, 2);

			lblFile = new Label();
			lblFile.Dock = DockStyle.Fill;
			lblFile.AutoSize = false;
			lblFile.TextAlign = ContentAlignment.MiddleLeft;
			lblFile.ForeColor = UiKit.Muted;
			lblFile.Margin = new Padding(0);
			fileLayout.Controls.Add(lblFile, 0, 3);

			TableLayoutPanel chatLayout = new TableLayoutPanel();
			chatLayout.Dock = DockStyle.Fill;
			chatLayout.ColumnCount = 1;
			chatLayout.RowCount = 3;
			chatLayout.BackColor = UiKit.Card;
			chatLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			chatLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48f));
			chatLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36f));
			chatPage.Controls.Add(chatLayout);

			logBox = new TextBox();
			logBox.Dock = DockStyle.Fill;
			logBox.Multiline = true;
			logBox.ReadOnly = true;
			logBox.ScrollBars = ScrollBars.Vertical;
			logBox.BackColor = Color.FromArgb(250, 251, 253);
			logBox.BorderStyle = BorderStyle.FixedSingle;
			logBox.Font = UiKit.Body;
			logBox.Margin = new Padding(0, 0, 0, 8);
			chatLayout.Controls.Add(logBox, 0, 0);

			TableLayoutPanel inputRow = new TableLayoutPanel();
			inputRow.Dock = DockStyle.Fill;
			inputRow.ColumnCount = 2;
			inputRow.RowCount = 1;
			inputRow.BackColor = UiKit.Card;
			inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
			inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 96f));
			inputRow.Margin = new Padding(0, 0, 0, 4);
			chatLayout.Controls.Add(inputRow, 0, 1);

			tbInput = new TextBox();
			tbInput.Dock = DockStyle.Fill;
			tbInput.Font = new Font("Microsoft YaHei UI", 10f);
			tbInput.BorderStyle = BorderStyle.FixedSingle;
			tbInput.Margin = new Padding(0, 4, 8, 0);
			UiKit.SetPlaceholder(tbInput, "输入消息，回车发送");
			inputRow.Controls.Add(tbInput, 0, 0);
			btnChatSend = UiKit.PrimaryButton("发送");
			btnChatSend.Dock = DockStyle.Fill;
			btnChatSend.Margin = new Padding(0, 2, 0, 0);
			inputRow.Controls.Add(btnChatSend, 1, 0);

			FlowLayoutPanel chatBottom = new FlowLayoutPanel();
			chatBottom.Dock = DockStyle.Fill;
			chatBottom.FlowDirection = FlowDirection.LeftToRight;
			chatBottom.WrapContents = false;
			chatBottom.BackColor = UiKit.Card;
			chatLayout.Controls.Add(chatBottom, 0, 2);
			btnClear = UiKit.SecondaryButton("清屏");
			btnClear.Width = 80;
			chatBottom.Controls.Add(btnClear);
			Button btnClearHistory = UiKit.SecondaryButton("清空历史");
			btnClearHistory.Width = 96;
			chatBottom.Controls.Add(btnClearHistory);
			btnClearHistory.Click += delegate
			{
				ClearHistory();
			};

			Panel status = UiKit.StatusBar(lblStatus = new Label());
			root.Controls.Add(status, 0, 2);

			btnScan.Click += delegate
			{
				Scan();
			};
			btnSend.Click += delegate
			{
				SendFiles();
			};
			btnOpenDir.Click += delegate
			{
				try
				{
					string text = FileTransferService.Current.ReceiveDir;
					if (string.IsNullOrEmpty(text))
					{
						text = Path.Combine(Program.DataDir, "Received");
					}
					Directory.CreateDirectory(text);
					Process.Start("explorer.exe", "\"" + text + "\"");
				}
				catch (Exception ex)
				{
					MessageBox.Show(this, "打不开接收文件夹：" + ex.Message, "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
				}
			};
			btnAddIp.Click += delegate
			{
				AddManualIp();
			};
			btnMute.Click += delegate
			{
				ToggleMuteSelected();
			};
			btnChatSend.Click += delegate
			{
				SendMessage();
			};
			btnClear.Click += delegate
			{
				logBox.Clear();
				logKeys.Clear();
			};
			btnSaveName.Click += delegate
			{
				SaveName();
			};
			tbMyName.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter)
				{
					e.SuppressKeyPress = true;
					SaveName();
				}
			};
			tbInput.KeyDown += delegate(object s, KeyEventArgs e)
			{
				if (e.KeyCode == Keys.Enter && !e.Shift)
				{
					e.SuppressKeyPress = true;
					SendMessage();
				}
			};
			peers.SelectedIndexChanged += delegate
			{
				UpdateActionButtons();
			};
			UpdateActionButtons();
			base.Load += delegate
			{
				FileTransferService current = FileTransferService.Current;
				current.OnLog = delegate(string m)
				{
					AppendTransferLog(m);
				};
				current.OnProgress = delegate(long done, long total, string name)
				{
					ShowProgress(done, total, name);
				};
			};
			base.FormClosed += delegate
			{
				FileTransferService current = FileTransferService.Current;
				if (current.OnLog != null)
				{
					current.OnLog = null;
				}
				if (current.OnProgress != null)
				{
					current.OnProgress = null;
				}
			};
			ResumeLayout();
		}

		private void UpdateActionButtons()
		{
			bool hasSelection = peers != null && peers.SelectedItems.Count > 0;
			if (btnSend != null)
			{
				btnSend.Enabled = !sending && hasSelection;
			}
			if (btnMute != null && btnMute.Visible)
			{
				btnMute.Enabled = hasSelection;
			}
		}

		private void ClearHistory()
		{
			if (MessageBox.Show(this, "将删除本机保存的聊天记录，其他电脑上的记录不受影响。\r\n联网时仍可能从其他电脑补回历史。是否继续？", "清空聊天历史", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
			{
				return;
			}
			FileTransferService.ClearChatLog();
			logBox.Clear();
			logKeys.Clear();
			historySynced = true;
			lblStatus.Text = "本机聊天历史已清空。";
		}

		private void AppendTransferLog(string msg)
		{
			SafeInvoke(delegate
			{
				if (transferLog == null || transferLog.IsDisposed)
				{
					return;
				}
				if (transferLog.TextLength > 30000)
				{
					transferLog.Clear();
				}
				transferLog.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + msg + "\r\n");
				transferLog.SelectionStart = transferLog.TextLength;
				transferLog.ScrollToCaret();
			});
		}
	}

	internal class IncomingDialog : Form
	{
		public string SaveDir;

		private TextBox tbDir;

		public IncomingDialog(TransferOffer offer, string initialDir)
		{
			Text = "收到文件传输请求";
			base.Size = new Size(620, 520);
			base.StartPosition = FormStartPosition.CenterParent;
			base.FormBorderStyle = FormBorderStyle.FixedDialog;
			base.MaximizeBox = false;
			base.MinimizeBox = false;
			UiKit.Apply(this);
			base.BackColor = Color.White;
			base.Padding = new Padding(24, 20, 24, 20);

			TableLayoutPanel layout = new TableLayoutPanel();
			layout.Dock = DockStyle.Fill;
			layout.ColumnCount = 1;
			layout.RowCount = 5;
			layout.BackColor = Color.White;
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
			layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 24f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42f));
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56f));
			base.Controls.Add(layout);

			Label info = new Label();
			info.Text = "来自 " + (string.IsNullOrEmpty(offer.SenderName) ? offer.SenderIp : offer.SenderName) + "（" + offer.SenderIp + "）的 " + offer.Files.Count + " 个文件，共 " + Util.FmtBytes(offer.Total);
			info.Font = UiKit.BodyBold;
			info.ForeColor = UiKit.TextColor;
			info.AutoSize = false;
			info.Dock = DockStyle.Fill;
			info.TextAlign = ContentAlignment.MiddleLeft;
			layout.Controls.Add(info, 0, 0);

			ListBox listBox = new ListBox();
			listBox.Dock = DockStyle.Fill;
			listBox.IntegralHeight = false;
			listBox.BorderStyle = BorderStyle.FixedSingle;
			listBox.Font = UiKit.Body;
			listBox.Margin = new Padding(0, 0, 0, 8);
			foreach (TransferEntry file in offer.Files)
			{
				listBox.Items.Add(file.Name + "    " + Util.FmtBytes(file.Size));
			}
			layout.Controls.Add(listBox, 0, 1);

			layout.Controls.Add(UiKit.FieldLabel("保存到"), 0, 2);

			TableLayoutPanel dirRow = new TableLayoutPanel();
			dirRow.Dock = DockStyle.Fill;
			dirRow.ColumnCount = 2;
			dirRow.RowCount = 1;
			dirRow.BackColor = Color.White;
			dirRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
			dirRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 96f));
			dirRow.Margin = new Padding(0, 4, 0, 0);
			layout.Controls.Add(dirRow, 0, 3);

			tbDir = new TextBox();
			tbDir.Dock = DockStyle.Fill;
			tbDir.BorderStyle = BorderStyle.FixedSingle;
			tbDir.Text = initialDir;
			tbDir.Margin = new Padding(0, 0, 8, 0);
			dirRow.Controls.Add(tbDir, 0, 0);
			Button button = UiKit.SecondaryButton("更改…");
			button.Dock = DockStyle.Fill;
			button.Margin = new Padding(0);
			dirRow.Controls.Add(button, 1, 0);
			button.Click += delegate
			{
				using (FolderBrowserDialog folderBrowserDialog = new FolderBrowserDialog())
				{
					folderBrowserDialog.SelectedPath = tbDir.Text;
					if (folderBrowserDialog.ShowDialog(this) == DialogResult.OK)
					{
						tbDir.Text = folderBrowserDialog.SelectedPath;
					}
				}
			};

			FlowLayoutPanel buttons = new FlowLayoutPanel();
			buttons.Dock = DockStyle.Fill;
			buttons.FlowDirection = FlowDirection.RightToLeft;
			buttons.WrapContents = false;
			buttons.BackColor = Color.White;
			layout.Controls.Add(buttons, 0, 4);
			Button button2 = UiKit.PrimaryButton("接收");
			button2.Width = 100;
			buttons.Controls.Add(button2);
			Button button3 = UiKit.SecondaryButton("拒绝");
			button3.Width = 100;
			button3.DialogResult = DialogResult.Cancel;
			buttons.Controls.Add(button3);
			base.CancelButton = button3;
			base.AcceptButton = button2;
			button2.Click += delegate
			{
				string text = tbDir.Text.Trim();
				if (text.Length == 0)
				{
					MessageBox.Show(this, "请选择保存目录。", "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
				}
				else
				{
					try
					{
						Directory.CreateDirectory(text);
					}
					catch (Exception ex)
					{
						MessageBox.Show(this, "无法创建目录：" + ex.Message, "NetGate", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
						return;
					}
					SaveDir = text;
					base.DialogResult = DialogResult.OK;
					Close();
				}
			};
		}
	}
	public sealed class LocalRelay
	{
		private TcpListener listener;

		private Thread acceptThread;

		private volatile bool running;

		private int localPort;

		private string targetIp;

		private int targetPort;

		private string mac;

		private string password;

		private readonly List<Socket> active = new List<Socket>();

		private readonly object sync = new object();

		public Action<string> Log;

		public bool Running
		{
			get
			{
				return running;
			}
		}

		public int LocalPort
		{
			get
			{
				return localPort;
			}
		}

		public bool Start(string ip, int port, string machineId, string pwd, out int boundPort, out string error)
		{
			boundPort = 0;
			error = null;
			Stop();
			try
			{
				targetIp = ip;
				targetPort = port;
				mac = machineId ?? "";
				password = pwd ?? "";
				listener = new TcpListener(IPAddress.Loopback, 0);
				listener.Start(64);
				localPort = ((IPEndPoint)listener.LocalEndpoint).Port;
				boundPort = localPort;
				running = true;
				acceptThread = new Thread(AcceptLoop);
				acceptThread.IsBackground = true;
				acceptThread.Start();
				DoLog("本机转发代理已启动：127.0.0.1:" + localPort + " -> " + targetIp + ":" + targetPort);
				return true;
			}
			catch (Exception ex)
			{
				error = ex.Message;
				Stop();
				return false;
			}
		}

		public void Stop()
		{
			running = false;
			try
			{
				if (listener != null)
				{
					listener.Stop();
				}
			}
			catch
			{
			}
			listener = null;
			lock (sync)
			{
				foreach (Socket item in active)
				{
					try
					{
						item.Close();
					}
					catch
					{
					}
				}
				active.Clear();
			}
		}

		private void AcceptLoop()
		{
			while (running)
			{
				TcpClient tcpClient = null;
				try
				{
					if (listener == null)
					{
						break;
					}
					tcpClient = listener.AcceptTcpClient();
				}
				catch
				{
					if (!running)
					{
						break;
					}
					continue;
				}
				TcpClient c = tcpClient;
				Thread thread = new Thread((ThreadStart)delegate
				{
					Handle(c);
				});
				thread.IsBackground = true;
				thread.Start();
			}
		}

		private void Handle(TcpClient client)
		{
			Socket upstream = null;
			try
			{
				client.NoDelay = true;
				Socket cs = client.Client;
				lock (sync)
				{
					active.Add(cs);
				}
				byte[] array = ReadHeader(client.GetStream());
				if (array == null || array.Length == 0)
				{
					return;
				}
				byte[] array2 = Inject(array);
				if (array2 != null)
				{
					upstream = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
					upstream.NoDelay = true;
					lock (sync)
					{
						active.Add(upstream);
					}
					IAsyncResult asyncResult = upstream.BeginConnect(targetIp, targetPort, null, null);
					if (!asyncResult.AsyncWaitHandle.WaitOne(10000))
					{
						throw new TimeoutException("连接控制端超时");
					}
					upstream.EndConnect(asyncResult);
					SendAll(upstream, array2);
					Thread thread = new Thread((ThreadStart)delegate
					{
						Pump(cs, upstream);
					});
					Thread thread2 = new Thread((ThreadStart)delegate
					{
						Pump(upstream, cs);
					});
					thread.IsBackground = true;
					thread2.IsBackground = true;
					thread.Start();
					thread2.Start();
					thread.Join();
					thread2.Join();
				}
			}
			catch (Exception ex)
			{
				DoLog("转发失败：" + ex.Message);
			}
			finally
			{
				try
				{
					client.Close();
				}
				catch
				{
				}
				try
				{
					if (upstream != null)
					{
						upstream.Close();
					}
				}
				catch
				{
				}
				lock (sync)
				{
					active.Remove(client.Client);
					if (upstream != null)
					{
						active.Remove(upstream);
					}
				}
			}
		}

		private static byte[] ReadHeader(NetworkStream st)
		{
			byte[] array = new byte[65536];
			int num = 0;
			while (num < array.Length)
			{
				int num2 = st.ReadByte();
				if (num2 < 0)
				{
					break;
				}
				array[num++] = (byte)num2;
				if (num >= 4 && array[num - 4] == 13 && array[num - 3] == 10 && array[num - 2] == 13 && array[num - 1] == 10)
				{
					break;
				}
			}
			if (num == 0)
			{
				return null;
			}
			byte[] array2 = new byte[num];
			Buffer.BlockCopy(array, 0, array2, 0, num);
			return array2;
		}

		private byte[] Inject(byte[] raw)
		{
			int num = -1;
			for (int i = 0; i + 3 < raw.Length; i++)
			{
				if (raw[i] == 13 && raw[i + 1] == 10 && raw[i + 2] == 13 && raw[i + 3] == 10)
				{
					num = i;
					break;
				}
			}
			if (num < 0)
			{
				return null;
			}
			string @string = Encoding.ASCII.GetString(raw, 0, num);
			string[] array = @string.Split(new string[1] { "\r\n" }, StringSplitOptions.None);
			if (array.Length == 0)
			{
				return null;
			}
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append(array[0]).Append("\r\n");
			for (int j = 1; j < array.Length; j++)
			{
				string text = array[j];
				if (!text.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase) && !text.StartsWith("X-NetGate-Mac:", StringComparison.OrdinalIgnoreCase))
				{
					stringBuilder.Append(text).Append("\r\n");
				}
			}
			stringBuilder.Append("X-NetGate-Mac: ").Append(mac).Append("\r\n");
			if (!string.IsNullOrEmpty(password))
			{
				string value = Convert.ToBase64String(Encoding.UTF8.GetBytes("netgate:" + password));
				stringBuilder.Append("Proxy-Authorization: Basic ").Append(value).Append("\r\n");
			}
			stringBuilder.Append("\r\n");
			byte[] bytes = Encoding.ASCII.GetBytes(stringBuilder.ToString());
			int num2 = raw.Length - (num + 4);
			byte[] array2 = new byte[bytes.Length + Math.Max(0, num2)];
			Buffer.BlockCopy(bytes, 0, array2, 0, bytes.Length);
			if (num2 > 0)
			{
				Buffer.BlockCopy(raw, num + 4, array2, bytes.Length, num2);
			}
			return array2;
		}

		private static void Pump(Socket src, Socket dst)
		{
			byte[] array = new byte[32768];
			try
			{
				while (true)
				{
					int num;
					try
					{
						num = src.Receive(array);
					}
					catch
					{
						break;
					}
					if (num > 0)
					{
						try
						{
							SendAll(dst, array, num);
						}
						catch
						{
							break;
						}
						continue;
					}
					break;
				}
			}
			finally
			{
				try
				{
					dst.Shutdown(SocketShutdown.Send);
				}
				catch
				{
				}
			}
		}

		private static void SendAll(Socket s, byte[] data)
		{
			SendAll(s, data, data.Length);
		}

		private static void SendAll(Socket s, byte[] data, int len)
		{
			int num;
			for (int i = 0; i < len; i += num)
			{
				num = s.Send(data, i, len - i, SocketFlags.None);
				if (num <= 0)
				{
					throw new SocketException(10054);
				}
			}
		}

		private void DoLog(string msg)
		{
			try
			{
				if (Log != null)
				{
					Log(msg);
				}
			}
			catch
			{
			}
		}
	}
}
