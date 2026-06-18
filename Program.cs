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
    var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
    var ip = packet.Extract<IPPacket>();

    if (ip == null) return;

    Console.WriteLine($"{raw.Timeval.Date:HH:mm:ss.fff}  {ip.Protocol,-4}  {ip.SourceAddress,-16} → {ip.DestinationAddress}");
}