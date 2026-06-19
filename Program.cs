using SharpPcap;
using PacketDotNet;

var devices = CaptureDeviceList.Instance;

if (devices.Count == 0)
{
    Console.WriteLine("No capture devices found. Try running as admin");
    return;
}

Console.WriteLine("Available interfaces:");
for (int i = 0; i < devices.Count; i++)
    Console.WriteLine($"  [{i}] {devices[i].Name} — {devices[i].Description}");

Console.Write("\nSelect interface index: ");
var index = int.Parse(Console.ReadLine()!);

var device = devices[index];
device.OnPacketArrival += OnPacketArrival;
device.Open(DeviceModes.Promiscuous, 1000);

Console.WriteLine($"\nCapturing on {device.Name}. Press CTRL+C to stop.\n");
device.StartCapture();
device.Filter = "udp port 53";

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;    
    device.StopCapture();
    device.Close();
    Console.WriteLine("\nCapture stopped.");
    Environment.Exit(0);
};

Thread.Sleep(Timeout.Infinite);

static void OnPacketArrival(object sender, PacketCapture e)
{
    var raw = e.GetPacket();
    byte[] data = raw.Data;

    if (data.Length < 14) return; // Too short to have an ethernet header

    ushort etherType = (ushort)((data[12] << 8) | data[13]);

    if (etherType == 0x0800)
    {
        ParseIPv4(data, offset: 14);
    }
    else if (etherType == 0x0806)
    {
        Console.WriteLine($"{raw.Timeval.Date:HH:mm:ss.fff} ARP");
    }
}

static void ParseIPv4(byte[] data, int offset)
{
    byte versionAndIhl = data[offset];
    int ihl = (versionAndIhl & 0x0F) * 4;
    byte protocol = data[offset + 9]; // The 9th byte reads the protocol

    string srcIp = $"{data[offset+12]}.{data[offset+13]}.{data[offset+14]}.{data[offset+15]}";
    string dstIp = $"{data[offset+16]}.{data[offset+17]}.{data[offset+18]}.{data[offset+19]}";

    int transportOffset = offset + ihl;

    switch (protocol)
    {
        case 6: ParseTcp(data, transportOffset, srcIp, dstIp); break;
        case 17: ParseUdp(data, transportOffset, srcIp, dstIp); break;
        case 1: Console.WriteLine($"ICMP  {srcIp} -> {dstIp}"); break;
        default: Console.WriteLine($"0x{protocol:X2}  {srcIp} -> {dstIp}"); break;
    }
}

static void ParseTcp(byte[] data, int offset, string srcIp, string dstIp)
{
    ushort srcPort = (ushort)((data[offset] << 8) | data[offset + 1]);
    ushort dstPort = (ushort)((data[offset + 2] << 8) | data[offset + 3]);

    byte flags = data[offset + 13];
    string flagStr = DecodeFlags(flags);

    Console.WriteLine($"TCP   {srcIp}:{srcPort} -> {dstIp}:{dstPort}  [{flagStr}]");
}

static string DecodeFlags(byte flags)
{
    var set = new List<string>();
    if ((flags & 0x01) != 0) set.Add("FIN");
    if ((flags & 0x02) != 0) set.Add("SYN");
    if ((flags & 0x04) != 0) set.Add("RST");
    if ((flags & 0x08) != 0) set.Add("PSH");
    if ((flags & 0x10) != 0) set.Add("ACK");
    if ((flags & 0x20) != 0) set.Add("URG");
    return string.Join(",", set);
}

static void ParseUdp(byte[] data, int offset, string srcIp, string dstIp)
{
    ushort srcPort = (ushort)((data[offset] << 8) | data[offset + 1]);
    ushort dstPort = (ushort)((data[offset + 2] << 8) | data[offset + 3]);
    ushort length = (ushort)((data[offset + 4] << 8) | data[offset + 5]);

    Console.WriteLine($"UDP   {srcIp}:{srcPort} -> {dstIp}:{dstPort}  len={length}");
}