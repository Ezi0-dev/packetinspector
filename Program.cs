using SharpPcap;
using PacketDotNet;

// Constants
const int EthernetHeaderLength = 14;
const ushort EtherTypeIPv4 = 0x0800;
const ushort EtherTypeArp = 0x0806;

const byte ProtoIcmp = 1;
const byte ProtoTcp = 6;
const byte ProtoUdp = 17;

const ushort DnsPort = 53;
const int DnsHeaderLength = 12;
const ushort DnsTypeA = 1;
const ushort DnsTypeAAAA = 28;

// Byte reading helpers
static ushort ReadUInt16BigEndian(byte[] data, int offset)
    => (ushort)((data[offset] << 8) | data[offset + 1]);

static uint ReadUInt32BigEndian(byte[] data, int offset)
    => (uint)((data[offset] << 24) | (data[offset + 1] << 16)
             | (data[offset + 2] << 8) | data[offset + 3]);

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
device.Filter = "udp port 53"; // Just for testing

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

    if (data.Length < EthernetHeaderLength) return; // Too short to have an ethernet header

    ushort etherType = ReadUInt16BigEndian(data, 12);

    if (etherType == EtherTypeIPv4)
    {
        ParseIPv4(data, offset: EthernetHeaderLength);
    }
    else if (etherType == EtherTypeArp)
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
        case ProtoTcp: ParseTcp(data, transportOffset, srcIp, dstIp); break;
        case ProtoUdp: ParseUdp(data, transportOffset, srcIp, dstIp); break;
        case ProtoIcmp: Console.WriteLine($"ICMP  {srcIp} -> {dstIp}"); break;
        default: Console.WriteLine($"0x{protocol:X2}  {srcIp} -> {dstIp}"); break;
    }
}

static void ParseTcp(byte[] data, int offset, string srcIp, string dstIp)
{
    ushort srcPort = ReadUInt16BigEndian(data, offset);
    ushort dstPort = ReadUInt16BigEndian(data, offset + 2);

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

    if (srcPort == DnsPort || dstPort == DnsPort) // Port 53
    {
        ParseDns(data, offset + 8, srcIp, dstIp);
        return;
    }

    Console.WriteLine($"UDP   {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
}

static void ParseDns(byte[] data, int offset, string srcIp, string dstIp)
{
    int messageStart = offset;

    ushort flags = ReadUInt16BigEndian(data, offset + 2);
    bool isResponse = (flags & 0x8000) != 0;

    ushort qdCount = ReadUInt16BigEndian(data, offset + 4);
    ushort anCount = ReadUInt16BigEndian(data, offset + 6);

    int pos = offset + DnsHeaderLength;

    // ── Question section ──
    string queryName = ReadDnsName(data, pos, messageStart, out pos);
    pos += 4; // skip QTYPE (2) + QCLASS (2) — we don't need them here

    if (!isResponse)
    {
        Console.WriteLine($"DNS   {srcIp} -> {dstIp}  query     {queryName}");
        return;
    }

    Console.WriteLine($"DNS   {srcIp} -> {dstIp}  response  {queryName}");

    // ── Answer section — this is the part we were skipping ──
    for (int i = 0; i < anCount; i++)
    {
        string name = ReadDnsName(data, pos, messageStart, out pos);

        ushort type = ReadUInt16BigEndian(data, pos);
        // skip TYPE(2) + CLASS(2) + TTL(4) = 8 bytes to reach RDLENGTH
        ushort rdLength = ReadUInt16BigEndian(data, pos + 8);
        int rdataOffset = pos + 10;

        if (type == DnsTypeA && rdLength == 4)
        {
            string ip = $"{data[rdataOffset]}.{data[rdataOffset+1]}.{data[rdataOffset+2]}.{data[rdataOffset+3]}";
            Console.WriteLine($"        -> A     {name} = {ip}");
        }
        else if (type == DnsTypeAAAA && rdLength == 16)
        {
            var groups = new string[8];
            for (int g = 0; g < 8; g++)
                groups[g] = ReadUInt16BigEndian(data, rdataOffset + g * 2).ToString("x");
            Console.WriteLine($"        -> AAAA  {name} = {string.Join(":", groups)}");
        }
        else
        {
            Console.WriteLine($"        -> type={type}  {name}  ({rdLength} bytes)");
        }

        pos = rdataOffset + rdLength; // advance past this record to the next one
    }
}

static string ReadDnsName(byte[] data, int pos, int messageStart, out int endPos)
{
    var labels = new List<string>();
    bool jumped = false;
    int originalPos = pos;

    while (true)
    {
        byte len = data[pos];

        if (len == 0)
        {
            pos++;
            break;
        }

        // Top two bits set = pointer (0xC0 = 1100 0000)
        if ((len & 0xC0) == 0xC0)
        {
            int pointerOffset = ((len & 0x3F) << 8) | data[pos + 1];
            if (!jumped) originalPos = pos + 2; // remember where to resume after jump
            pos = messageStart + pointerOffset;
            jumped = true;
            continue;
        }

        // Normal label
        pos++;
        labels.Add(System.Text.Encoding.ASCII.GetString(data, pos, len));
        pos += len;
    }

    endPos = jumped ? originalPos : pos;
    return string.Join(".", labels);
}