using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace TrigonServer;

class Program
{
    private static TcpListener _tcpListener;
    private static List<TcpClient> _tcpClients = new List<TcpClient>();
    private static object _lockObj = new object();
    private static string password = "";
    private static Dictionary<string, string> users = new Dictionary<string, string>();
    
    static void Main(string[] args)
    {
        Console.Write("Please input the server port: ");
        int port = Convert.ToInt32(Console.ReadLine());
        password = GeneratePassword();
        Logger.LogInfo($"Server password is: {password}");
        Start(port);
        
    }
    
    static void Start(int port)
    {
        _tcpListener = new TcpListener(IPAddress.Any, port);
        _tcpListener.Start();
        Logger.LogInfo($"Server started on port {port}");

        while (true)
        {
            TcpClient client = _tcpListener.AcceptTcpClient();
            lock (_lockObj) _tcpClients.Add(client);
            Logger.LogInfo("Client connected.");

            Thread thread = new Thread(HandleClient);
            thread.Start(client);
        }
    }
    
    private static void HandleClient(object obj)
    {
        TcpClient client = (TcpClient)obj;
        NetworkStream stream = client.GetStream();
        byte[] buffer = new byte[4096];

        try
        {
            while (true)
            {
                int bytes = stream.Read(buffer, 0, buffer.Length);
                if (bytes == 0) break;
                
                string message = Encoding.UTF8.GetString(buffer, 0, bytes);
                Logger.LogMessage($"{message}");
                try
                {
                    Message messageStruct = DecryptMessage(message);
                    if (messageStruct.MessageString != "{Connect}" && messageStruct.MessageString != "{Disconnect}")
                        BroadcastMessage(message, client);

                    if (messageStruct.MessageString == "{Disconnect}")
                    {
                        _tcpClients.Remove(client);
                        client.Close();
                    }
                }
                catch (AuthenticationException e)
                {
                    Logger.LogError(e.Message);
                    _tcpClients.Remove(client);
                    client.Close();
                }
                catch (Exception e)
                {
                    Logger.LogError(e.Message);
                }
                // int bytes = JsonConvert.SerializeObject(new Message("Ilonic", "Hi", "123", "123")).Length;
                // string message =
                //     Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new Message("Ilonic", "Hi", "123", "123"))), 0,
                //         bytes);
                // BroadcastMessage(message, client);
                // Thread.Sleep(3000);
            }
        }
        catch (Exception ex)
        {
            Logger.LogWarning("Client disconnected: " + ex.Message);
        }
        finally
        {
            lock (_lockObj) _tcpClients.Remove(client);
            client.Close();
        }
    }
    private static void BroadcastMessage(string message, TcpClient sender)
    {
        byte[] data = Encoding.UTF8.GetBytes(message);

        lock (_lockObj)
        {
            foreach (TcpClient client in _tcpClients)
            {
                if (client == sender) continue;
                try
                {
                    NetworkStream stream = client.GetStream();
                    stream.Write(data, 0, data.Length);
                }
                catch
                {
                    // Remove unreachable clients
                    _tcpClients.Remove(client);
                }
            }
        }
    }
    private static string GeneratePassword()
    {
        string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789!@#$%^&*()";
        string password = "";
        Random rnd = new Random();
    
        for (int i = 0; i < 24; i++) password += table[rnd.Next(0, table.Length)];
        password += '.';
        for (int i = 0; i < 16; i++) password += table[rnd.Next(0, table.Length)];
        return password;
    }

    private static Message DecryptMessage(string message)
    {
        Message msg = JsonConvert.DeserializeObject<Message>(message);
        
        AesEncryption encryption = new AesEncryption(password);
        string usrPwd;
        string messageString;
        
        if (users.ContainsKey(msg.From))
        {
            if (msg.UserPassword != users[msg.From])
                throw new AuthenticationException("Authorization Error: Incorrect password!");
            usrPwd = encryption.Decrypt(users[msg.From]);
        }
        else
        {
            usrPwd = encryption.Decrypt(msg.UserPassword);
            users.Add(msg.From, msg.UserPassword);
        }
        
        messageString =
            new AesEncryption(usrPwd, Encoding.UTF8.GetString(encryption.IV)).Decrypt(msg.MessageString);
        string msgHash = Utilities.SHA256Hash(messageString);
        if (msgHash != msg.MessageHash)
            throw new Exception("Authorization Error: Invalid message hash or password.");
        msg.MessageString = messageString;
        return msg;
    }
}
class Logger
{
    public static void LogSuccess(string message)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("[+] {0}" ,message);
        Console.ResetColor();
    }
    
    public static void LogInfo(string message)
    {
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("[i] {0}" ,message);
        Console.ResetColor();
    }
    
    public static void LogWarning(string message)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[!] {0}" ,message);
        Console.ResetColor();
    }
    
    public static void LogError(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("[X] {0}" ,message);
        Console.ResetColor();
    }
    
    public static void LogMessage(string message)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("[M] {0}" ,message);
        Console.ResetColor();
    }
}
