using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using NetGateApp;

internal static class PeerTest
{
    private static void Main(string[] args)
    {
        string mode = (args != null && args.Length > 0) ? args[0] : "";
        bool holder = mode == "hold";

        FileTransferService svc = FileTransferService.Current;
        svc.Start();
        FileTransferService.ChatArrived += delegate(ChatMessage m)
        {
            string line = "CHAT-RECV " + m.FromName + " (" + m.FromIp + "): " + m.Text;
            try
            {
                Console.WriteLine(line);
                Console.Out.Flush();
            }
            catch
            {
            }
            try
            {
                File.AppendAllText("chat-received.txt", line + "\r\n", new UTF8Encoding(false));
            }
            catch
            {
            }
        };
        Console.WriteLine("PEER id=" + svc.LocalId + " tcp=" + svc.TcpListenPort + " udp=" + svc.UdpListenPort + " name=" + svc.LocalName);
        Console.Out.Flush();

        if (mode == "hist")
        {
            // 用法：peer.exe hist <ip[:port]>   拉对方的聊天记录
            if (args.Length < 2)
            {
                Console.WriteLine("用法: peer.exe hist <ip[:port]>");
                return;
            }
            TransferPeer target = svc.ProbePeer(args[1], 1500);
            if (target == null && args[1].IndexOf(':') > 0)
            {
                string[] parts = args[1].Split(':');
                int tcpPort;
                if (int.TryParse(parts[1], out tcpPort))
                {
                    target = new TransferPeer();
                    target.Id = "direct:" + args[1];
                    target.Ip = parts[0];
                    target.Port = tcpPort;
                    target.Name = args[1];
                }
            }
            if (target == null)
            {
                Console.WriteLine("HIST FAIL: 找不到对方");
                return;
            }
            List<ChatMessage> hist = svc.FetchHistory(target, 50);
            Console.WriteLine("HIST count=" + hist.Count + " from " + target.Ip + ":" + target.Port);
            foreach (ChatMessage m in hist)
            {
                Console.WriteLine("  " + m.At.ToString("yyyy-MM-dd HH:mm:ss") + " [" + m.FromName + "] " + m.Text);
            }
            Console.Out.Flush();
            svc.Stop();
            return;
        }

        if (mode == "chat-serve")
        {
            Console.WriteLine("CHAT-SERVE ready tcp=" + svc.TcpListenPort);
            Console.Out.Flush();
            Thread.Sleep(12000);
            svc.Stop();
            return;
        }

        if (mode == "chat-all")
        {
            // 用法：peer.exe chat-all <text>   群发给所有能发现的电脑
            string body = (args != null && args.Length > 1) ? args[1] : "群聊测试";
            List<TransferPeer> list = svc.Discover(2000);
            Console.WriteLine("成员 " + list.Count + " 台");
            int failed;
            int ok = svc.SendChatAll(body, list, out failed);
            Console.WriteLine("CHAT-ALL ok=" + ok + " failed=" + failed);
            Console.Out.Flush();
            svc.Stop();
            return;
        }

        if (mode == "chat")
        {
            // 用法：peer.exe chat <ip[:port]> <text>
            if (args.Length < 3)
            {
                Console.WriteLine("用法: peer.exe chat <ip[:port]> <text>");
                return;
            }
            TransferPeer target = svc.ProbePeer(args[1], 1500);
            if (target == null && args[1].IndexOf(':') > 0)
            {
                string[] parts = args[1].Split(':');
                int tcpPort;
                if (int.TryParse(parts[1], out tcpPort))
                {
                    target = new TransferPeer();
                    target.Id = "direct:" + args[1];
                    target.Ip = parts[0];
                    target.Port = tcpPort;
                    target.Name = args[1];
                }
            }
            if (target == null)
            {
                Console.WriteLine("CHAT-SEND FAIL: 找不到接收方");
                svc.Stop();
                return;
            }
            string error;
            string r = svc.SendChat(target, args[2], out error);
            Console.WriteLine("CHAT-SEND " + ((r == null) ? ("FAIL: " + error) : ("OK -> " + target.Ip + ":" + target.Port)));
            Console.Out.Flush();
            svc.Stop();
            return;
        }

        if (mode == "serve")
        {
            // 免确认接收，用于自动化验证文件传输链路
            string dir = Path.Combine(Path.GetTempPath(), "netgate_recv_test");
            Directory.CreateDirectory(dir);
            svc.ReceiveDir = dir;
            svc.AutoAccept = delegate(TransferOffer o)
            {
                Console.WriteLine("OFFER from " + o.SenderIp + " files=" + o.Files.Count + " total=" + o.Total);
                Console.Out.Flush();
                return dir;
            };
            Console.WriteLine("SERVE dir=" + dir + " tcp=" + svc.TcpListenPort);
            Console.Out.Flush();
            Thread.Sleep(10000);
            svc.Stop();
            return;
        }

        if (mode == "send")
        {
            // 用法：peer.exe send <ip[:port]> <file>
            if (args.Length < 3)
            {
                Console.WriteLine("用法: peer.exe send <ip[:port]> <file>");
                return;
            }
            TransferPeer peer = svc.ProbePeer(args[1], 1500);
            if (peer == null && args[1].IndexOf(':') > 0)
            {
                string[] parts = args[1].Split(':');
                int tcpPort;
                if (int.TryParse(parts[1], out tcpPort))
                {
                    peer = new TransferPeer();
                    peer.Id = "direct:" + args[1];
                    peer.Ip = parts[0];
                    peer.Port = tcpPort;
                    peer.Name = args[1];
                }
            }
            Console.WriteLine("TARGET " + args[1] + " -> " + ((peer == null) ? "无应答" : ("id=" + peer.Id + " ip=" + peer.Ip + " port=" + peer.Port + " name=" + peer.Name)));
            if (peer == null)
            {
                svc.Stop();
                return;
            }
            string error;
            string r = svc.Send(peer, new string[1] { args[2] }, delegate(long done, long total, string name)
            {
            }, out error);
            Console.WriteLine("SEND " + ((r == null) ? ("FAIL: " + error) : ("OK -> " + r)));
            Console.Out.Flush();
            svc.Stop();
            return;
        }

        if (mode == "probe")
        {
            // 用法：peer.exe probe 192.168.1.5[:8896]
            if (args.Length < 2)
            {
                Console.WriteLine("用法: peer.exe probe <ip[:port]>");
                return;
            }
            for (int round = 0; round < 3; round++)
            {
                TransferPeer hit = svc.ProbePeer(args[1], 1500);
                Console.WriteLine("PROBE " + args[1] + " round=" + round + " -> " +
                    ((hit == null) ? "无应答" : ("id=" + hit.Id + " ip=" + hit.Ip + " port=" + hit.Port + " name=" + hit.Name)));
                Console.Out.Flush();
                if (hit != null)
                {
                    break;
                }
            }
            svc.Stop();
            return;
        }

        if (mode == "name")
        {
            // 用法：peer.exe name <新名字>   然后 sleep 让其它进程扫描验证
            if (args.Length >= 2)
            {
                svc.SetLocalName(args[1]);
                Console.WriteLine("NAME " + svc.LocalName);
                Console.Out.Flush();
            }
            Thread.Sleep(8000);
            svc.Stop();
            return;
        }

        Thread.Sleep(holder ? 2500 : 1000);

        List<TransferPeer> peers = svc.Discover(2500);
        Console.WriteLine("FOUND " + peers.Count);
        foreach (TransferPeer p in peers)
        {
            Console.WriteLine("  - id=" + p.Id + " ip=" + p.Ip + " port=" + p.Port + " name=" + p.Name);
        }
        Console.Out.Flush();

        if (holder)
        {
            Thread.Sleep(6000);
        }
        else
        {
            Thread.Sleep(500);
        }
        svc.Stop();
    }
}
