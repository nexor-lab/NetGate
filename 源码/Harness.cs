using System;
using System.IO;
using System.Threading;
using NetGateCore;

internal static class Harness
{
    private static void Main()
    {
        string dir = "C:\\Users\\hbxx\\Documents\\deepseek-harness\\default-workspace\\dsh-netgate\\harness-data";
        Directory.CreateDirectory(dir);
        NetGateServer.LogPath = Path.Combine(dir, "engine.log");

        EngineOptions opt = new EngineOptions();
        opt.ListenPort = 18899;
        NetGateServer server = NetGateServer.Create(opt);
        lock (server.StateLock)
        {
            server.PasswordHash = "798da58d118779de9f91b0ec3e22bfaccf6dd48d44788d191ccad9534c02d484";
            server.GatewayName = "HARNESS";
        }
        server.SetAllowed("020000000001", true);
        server.Start();
        Console.WriteLine("HARNESS-READY port=18899");
        Thread.Sleep(120000);
        server.Stop();
    }
}
