using SharpPcap;
using PacketDotNet;
using System.Text.Json;
using System.Text.Json.Serialization;
using Spectre.Console;
using System.Collections.Concurrent;

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

// Shared state vars (capture thread and main thread) - for TUI
var packetQueue = new ConcurrentQueue<ParsedPacket>();
long totalPackets = 0;
long tcpCount = 0;
long udpCount = 0;
long dnsCount = 0;
long httpCount = 0;
var recentPackets = new Queue<ParsedPacket>(); // last N packets for the table
var topIps = new Dictionary<string, int>();    // dst IP → count

FilterNode? filterAst = null;
BinaryWriter? pcapWriter = null;

bool pcapMode = args.Contains("--output-pcap"); // PCAP mode
bool jsonMode = args.Contains("--output-json"); // JSON mode
bool tuiMode = args.Contains("--output-tui");

// TUI layout
Table BuildLayout()
{
    long total = Interlocked.Read(ref totalPackets);
    long tcp = Interlocked.Read(ref tcpCount);
    long udp = Interlocked.Read(ref udpCount);
    long dns = Interlocked.Read(ref dnsCount);
    long http = Interlocked.Read(ref httpCount);

    var statsTable = new Table().NoBorder().HideHeaders();
    statsTable.AddColumn("").AddColumn("").AddColumn("");

    var totalPanel = new Panel($"[red]{total:N0}[/]\n[grey]packets[/]")
        .Header("Total").BorderColor(Color.Grey);

    var protoPanel = new Panel(
        $"[blue]TCP  {tcp,6:N0}[/]\n[green]UDP  {udp,6:N0}[/]\n[yellow]DNS  {dns,6:N0}[/]\n[red]HTTP {http,6:N0}[/]")
        .Header("Protocols").BorderColor(Color.Grey);

    var topIpsSorted = topIps.OrderByDescending(kv => kv.Value).Take(3);
    string topIpsText = string.Join("\n", topIpsSorted.Select((kv, i) => $"{i+1}. {kv.Key,-18} {kv.Value}"));
    var topPanel = new Panel(topIpsText.Length > 0 ? topIpsText : "[grey]waiting...[/]")
        .Header("Top Destinations").BorderColor(Color.Grey);

    statsTable.AddRow(totalPanel, protoPanel, topPanel);

    // Recent packets table
    var packetTable = new Table()
        .Border(TableBorder.Rounded)
        .BorderColor(Color.Grey)
        .AddColumn("[grey]Time[/]")
        .AddColumn("[grey]Proto[/]")
        .AddColumn("[grey]Source[/]")
        .AddColumn("[grey]Destination[/]")
        .AddColumn("[grey]Info[/]");
    
    foreach (var pkt in recentPackets)
    {
        string proto = pkt.Protocol.ToUpper();
        string color = pkt.Protocol switch
        {
            "tcp"  => "blue",
            "udp"  => "green",
            "dns"  => "yellow",
            "http" => "red",
            _      => "white"
        };
        string info = pkt.DnsName ?? (pkt.HttpStatus?.ToString() ?? "");
        packetTable.AddRow(
            $"[grey]{pkt.Timestamp}[/]",
            $"[{color}]{proto}[/]",
            $"{pkt.SrcIp}:{pkt.SrcPort}",
            $"{pkt.DstIp}:{pkt.DstPort}",
            info
        );
    }

    var layout = new Table().NoBorder().HideHeaders().Expand();
    layout.AddColumn("");
    layout.AddRow(new Panel(statsTable).Header("[red]⚡ PacketInspector[/]").Expand());
    layout.AddRow(packetTable);
    return layout;
}

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

Console.Write("Enter filter (or press Enter for no filter): ");
string filterInput = Console.ReadLine() ?? "";

if (!string.IsNullOrWhiteSpace(filterInput)) //
{
    try
    {
        var tokens = Tokenize(filterInput);
        filterAst = new FilterParser(tokens).Parse();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Invalid filter: {ex.Message}");
        return;
    }
}



var device = devices[index];
device.OnPacketArrival += OnPacketArrival;
device.Open(DeviceModes.Promiscuous, 1000);


Console.WriteLine($"\nCapturing on {device.Name}. Press CTRL+C to stop.\n");


device.StartCapture();
//device.Filter = "tcp port 80"; // Just for testing

if (tuiMode)
{
    AnsiConsole.Live(BuildLayout())
        .AutoClear(true)
        .Overflow(VerticalOverflow.Ellipsis)
        .Start(ctx =>
        {
            while (true)
            {
                // Drain the queue (process everything the capture thread enqueued)
                while (packetQueue.TryDequeue(out var pkt))
                {
                    Interlocked.Increment(ref totalPackets);

                    switch (pkt.Protocol)
                    {
                        case "tcp":  Interlocked.Increment(ref tcpCount);  break;
                        case "udp":  Interlocked.Increment(ref udpCount);  break;
                        case "dns":  Interlocked.Increment(ref dnsCount);  break;
                        case "http": Interlocked.Increment(ref httpCount); break;
                    }

                    if (!string.IsNullOrEmpty(pkt.DstIp))
                    {
                        topIps.TryGetValue(pkt.DstIp, out int count);
                        topIps[pkt.DstIp] = count + 1;
                    }

                    recentPackets.Enqueue(pkt);
                    if (recentPackets.Count > 8) recentPackets.Dequeue(); // Keep last 8
                }

                ctx.UpdateTarget(BuildLayout());
                ctx.Refresh();
                Thread.Sleep(250); // 4 renders per second
            }
        });
}

if (pcapMode)
{
    string filename = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap";
    var stream = new FileStream(filename, FileMode.Create, FileAccess.Write);
    pcapWriter = new BinaryWriter(stream);
    WritePcapGlobalHeader(pcapWriter);
    Console.Error.WriteLine($"Writing to {filename}");
}

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;    
    device.StopCapture();
    device.Close();
    pcapWriter?.Flush();
    pcapWriter?.Close();
    Console.WriteLine("\nCapture stopped.");
    Environment.Exit(0);
};

Thread.Sleep(Timeout.Infinite);

void OnPacketArrival(object sender, PacketCapture e)
{
    var raw = e.GetPacket();
    byte[] data = raw.Data;

    if (pcapMode && pcapWriter != null)
    {
        WritePcapPacket(pcapWriter, e);
        pcapWriter.Flush();
    }

    if (data.Length < EthernetHeaderLength) return;

    ushort etherType = ReadUInt16BigEndian(data, 12);
    if (etherType != EtherTypeIPv4) return;

    ParsedPacket? packet = ParseIPv4(data, EthernetHeaderLength);
    if (packet == null) return;

    if (filterAst != null && !Evaluate(filterAst, packet))
        return; // doesn't match — skip
    
    packet = packet with { Timestamp = raw.Timeval.Date.ToString("HH:mm:ss.fff") };

    if (jsonMode)
    {
        var options = new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
        Console.WriteLine(JsonSerializer.Serialize(packet, options));
    }

    if (tuiMode)
    {
        packetQueue.Enqueue(packet); // Let main thread handle it
        return;
    }

    Console.WriteLine($"{raw.Timeval.Date:HH:mm:ss.fff}  {packet.Protocol.ToUpper(),-5} {packet.SrcIp}:{packet.SrcPort} -> {packet.DstIp}:{packet.DstPort}" 
        + (packet.DnsName != null ? $"  {packet.DnsName}" : "")
        + (packet.HttpStatus != null ? $"  status={packet.HttpStatus}" : ""));
}

static ParsedPacket? ParseIPv4(byte[] data, int offset)
{
    byte versionAndIhl = data[offset];
    int ihl = (versionAndIhl & 0x0F) * 4;
    byte protocol = data[offset + 9]; // The 9th byte reads the protocol

    string srcIp = $"{data[offset+12]}.{data[offset+13]}.{data[offset+14]}.{data[offset+15]}";
    string dstIp = $"{data[offset+16]}.{data[offset+17]}.{data[offset+18]}.{data[offset+19]}";

    int transportOffset = offset + ihl;

    return protocol switch
    {
        ProtoTcp => ParseTcp(data, transportOffset, srcIp, dstIp),
        ProtoUdp => ParseUdp(data, transportOffset, srcIp, dstIp),
        _ => null
    };
}

static ParsedPacket? ParseTcp(byte[] data, int offset, string srcIp, string dstIp)
{
    ushort srcPort = ReadUInt16BigEndian(data, offset);
    ushort dstPort = ReadUInt16BigEndian(data, offset + 2);
    byte flags = data[offset + 13];

    int tcpHeaderLength = ((data[offset + 12] >> 4) & 0x0F) * 4;
    int payloadOffset = offset + tcpHeaderLength;
    int payloadLength = data.Length - payloadOffset;

    if ((srcPort == 80 || dstPort == 80) && payloadLength > 0)
    {
        var httpPacket = ParseHttp(data, payloadOffset, payloadLength, srcIp, dstIp);
        if (httpPacket != null) return httpPacket; // HTTP takes priority if found
    }

    return new ParsedPacket("tcp", srcIp, dstIp, srcPort, dstPort);
}

static ParsedPacket? ParseUdp(byte[] data, int offset, string srcIp, string dstIp)
{
    ushort srcPort = (ushort)((data[offset] << 8) | data[offset + 1]);
    ushort dstPort = (ushort)((data[offset + 2] << 8) | data[offset + 3]);

    if (srcPort == DnsPort || dstPort == DnsPort) // Port 53
    {
        var dnsPacket = ParseDns(data, offset + 8, srcIp, dstIp);
        if (dnsPacket != null) return dnsPacket;
    }

    return new ParsedPacket("udp", srcIp, dstIp, srcPort, dstPort);
}

static ParsedPacket? ParseDns(byte[] data, int offset, string srcIp, string dstIp)
{
    int messageStart = offset;

    ushort flags = ReadUInt16BigEndian(data, offset + 2);
    bool isResponse = (flags & 0x8000) != 0;

    ushort anCount = ReadUInt16BigEndian(data, offset + 6);

    int pos = offset + DnsHeaderLength;

    // Question section 
    string queryName = ReadDnsName(data, pos, messageStart, out pos);
    pos += 4; // skip QTYPE (2) + QCLASS (2) — we don't need them here

    if (!isResponse)
    {
        return new ParsedPacket("dns", srcIp, dstIp, DnsName: queryName);
    }

    // Answer section, this is the part we were skipping
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

        pos = rdataOffset + rdLength; // advance past this record to the next one
    }

    return new ParsedPacket("dns", srcIp, dstIp, DnsName: queryName);
}

static ParsedPacket? ParseHttp(byte[] data, int offset, int length, string srcIp, string dstIp)
{
    string text = System.Text.Encoding.ASCII.GetString(data, offset, length);
    int headerEnd = text.IndexOf("\r\n\r\n");
    string headerSection = headerEnd >= 0 ? text[..headerEnd] : text;
    string[] lines = headerSection.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
    
    if (lines.Length == 0) return null;
    string firstLine = lines[0];

    if (firstLine.StartsWith("HTTP/"))
    {
        var parts = firstLine.Split(' ');
        int? status = parts.Length > 1 && int.TryParse(parts[1], out var s) ? s : null;
        return new ParsedPacket("http", srcIp, dstIp, HttpStatus: status);
    }
    else if (firstLine.Contains("HTTP/"))
    {
        return new ParsedPacket("http", srcIp, dstIp);
    }

    return null;
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

        // Top two bits set = pointer (0xC0 = 1100 0000), (jump to pointer)
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

static void WritePcapGlobalHeader(BinaryWriter writer)
{
    writer.Write(0xA1B2C3D4u); // magic number — makes the file an actual pcap file so wireshark can read it
    writer.Write((ushort)2);   // major version
    writer.Write((ushort)4);   // minor version
    writer.Write(0);           // UTC offset — always 0
    writer.Write(0);           // timestamp accuracy — always 0
    writer.Write(65535u);      // snaplen — max packet size
    writer.Write(1u);          // link type 1 = Ethernet
}

static void WritePcapPacket(BinaryWriter writer, PacketCapture e)
{
    var raw = e.GetPacket();
    byte[] data = raw.Data;

    uint seconds = (uint)raw.Timeval.Seconds;
    uint microseconds = (uint)raw.Timeval.MicroSeconds;
    uint capturedLength = (uint)data.Length;
    uint originalLength = (uint)data.Length;

    writer.Write(seconds);
    writer.Write(microseconds);
    writer.Write(capturedLength);
    writer.Write(originalLength);
    writer.Write(data);
}

// Byte reading helpers
static ushort ReadUInt16BigEndian(byte[] data, int offset)
    => (ushort)((data[offset] << 8) | data[offset + 1]); // << 8 = 2^8, so 0x01 = 256

static uint ReadUInt32BigEndian(byte[] data, int offset)
    => (uint)((data[offset] << 24) | (data[offset + 1] << 16)
             | (data[offset + 2] << 8) | data[offset + 3]);

static List<Token> Tokenize(string input)
{
    var tokens = new List<Token>();
    var words = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    foreach (var word in words)
    {
        TokenType type = word.ToLower() switch
        {
            "and" => TokenType.And,
            "or" => TokenType.Or,
            "not" => TokenType.Not,
            _ when int.TryParse(word, out _) => TokenType.Number,
            _ => TokenType.Ident
        };
        tokens.Add(new Token(type, word));
        
    }

    tokens.Add(new Token(TokenType.Eof, ""));
    return tokens;
}

static bool Evaluate(FilterNode node, ParsedPacket packet) => node switch
{
    ProtocolNode p => packet.Protocol == p.Protocol,
    PortNode p => packet.SrcPort == p.Port || packet.DstPort == p.Port,
    SrcIpNode s => packet.SrcIp == s.Ip,
    AndNode a => Evaluate(a.Left, packet) && Evaluate(a.Right, packet),
    OrNode o => Evaluate(o.Left, packet) || Evaluate(o.Right, packet),
    NotNode n => !Evaluate(n.Inner, packet),
    _ => false
};

class FilterParser
{
    private readonly List<Token> _tokens;
    private int _pos = 0;

    public FilterParser(List<Token> tokens) => _tokens = tokens;

    private Token Current => _tokens[_pos];
    private Token Advance() => _tokens[_pos++];

    public FilterNode Parse() => ParseOr();

    private FilterNode ParseOr()
    {
        var left = ParseAnd();
        while (Current.Type == TokenType.Or)
        {
            Advance();
            var right = ParseAnd();
            left = new OrNode(left, right);
        }
        return left;
    }

    private FilterNode ParseAnd() // And binds tighter than OR, ex = tcp or (udp and port 443)
    {
        var left = ParseTerm();
        while (Current.Type == TokenType.And)
        {
            Advance();
            var right = ParseTerm();
            left = new AndNode(left, right);
        }
        return left;
    }

    private FilterNode ParseTerm()
    {
        if (Current.Type == TokenType.Not)
        {
            Advance();
            return new NotNode(ParseTerm());
        }

        var token = Advance();

        if (token.Text.ToLower() is "tcp" or "udp" or "dns" or "http")
            return new ProtocolNode(token.Text.ToLower());

        if (token.Text.ToLower() == "port")
        {
            var portToken = Advance();
            return new PortNode(int.Parse(portToken.Text));
        }

        if (token.Text.ToLower() == "src")
        {
            var ipToken = Advance();
            return new SrcIpNode(ipToken.Text);
        }

        throw new FormatException($"Unexpected token: {token.Text}");
    }
}

record ParsedPacket(
    string Protocol,      // "tcp", "udp", "dns", "http"
    string SrcIp,
    string DstIp,
    ushort? SrcPort = null,
    ushort? DstPort = null,
    string? DnsName = null,
    int? HttpStatus = null,
    string? Timestamp = null
);

enum TokenType { Ident, Number, And, Or, Not, Eof }
record Token(TokenType Type, string Text);
abstract record FilterNode;
record ProtocolNode(string Protocol) : FilterNode;
record PortNode(int Port) : FilterNode;
record SrcIpNode(string Ip) : FilterNode;
record AndNode(FilterNode Left, FilterNode Right) : FilterNode;
record OrNode(FilterNode Left, FilterNode Right) : FilterNode;
record NotNode(FilterNode Inner) : FilterNode;






