using Newtonsoft.Json;

namespace TrigonServer;

public struct Message
{
    public string From { get; set; }
    public string MessageString { get; set; }
    public string UserPassword { get; set; }
    public string MessageHash { get; set; }
    public Message(string input)
    {
        JsonConvert.DeserializeObject<Message>(input);
    }

    public Message(string from, string messageString, string userPassword, string messageHash)
    {
        From = from;
        MessageString = messageString;
        UserPassword = userPassword;
        MessageHash = messageHash;
    }
}