using SharpPcap;
using PacketDotNet;
using System.Text.Json;
using System.Text.Json.Serialization;

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

FilterNode? filterAst = null;

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

if (!string.IsNullOrWhiteSpace(filterInput))
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

bool jsonMode = args.Contains("--output-json"); // JSON mode

var device = devices[index];
device.OnPacketArrival += OnPacketArrival;
device.Open(DeviceModes.Promiscuous, 1000);
Console.WriteLine($"\nCapturing on {device.Name}. Press CTRL+C to stop.\n");
device.StartCapture();
//device.Filter = "tcp port 80"; // Just for testing

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;    
    device.StopCapture();
    device.Close();
    Console.WriteLine("\nCapture stopped.");
    Environment.Exit(0);
};

Thread.Sleep(Timeout.Infinite);

void OnPacketArrival(object sender, PacketCapture e)
{
    var raw = e.GetPacket();
    byte[] data = raw.Data;

    if (data.Length < EthernetHeaderLength) return;

    ushort etherType = ReadUInt16BigEndian(data, 12);
    if (etherType != EtherTypeIPv4) return;

    ParsedPacket? packet = ParseIPv4(data, EthernetHeaderLength);
    if (packet == null) return;

    if (filterAst != null && !Evaluate(filterAst, packet))
        return; // doesn't match — skip silently, no output at all

    packet = packet with { Timestamp = raw.Timeval.Date.ToString("HH:mm:ss.fff") };

    if (jsonMode)
    {
        var options = new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
        Console.WriteLine(JsonSerializer.Serialize(packet, options));
    }
    else
    {
        Console.WriteLine($"{raw.Timeval.Date:HH:mm:ss.fff}  {packet.Protocol.ToUpper(),-5} {packet.SrcIp}:{packet.SrcPort} -> {packet.DstIp}:{packet.DstPort}" 
            + (packet.DnsName != null ? $"  {packet.DnsName}" : "")
            + (packet.HttpStatus != null ? $"  status={packet.HttpStatus}" : ""));
    }
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






