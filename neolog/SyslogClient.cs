/*
 * Florian Roth
 * Syslog Client Class
 */

using System;
using System.Net;
using System.Net.Sockets;

namespace SyslogClient

{
    public enum Level
    {
        Emergency = 0,
        Alert = 1,
        Critical = 2,
        Error = 3,
        Warning = 4,
        Notice = 5,
        Information = 6,
        Debug = 7,
    }


    public enum Facility
    {
        kernel = 0,       
        user = 1,
        mail = 2,
        daemon = 3,
        auth = 4,
        syslog = 5,
        lpr = 6,
        news = 7,
        uucp = 8,
        cron = 9,
        security = 10,
        ftp = 11,
        ntp = 12,
        audit = 13,
        alert = 14,
        clock = 15,
        local0 = 16,
        local1 = 17,
        local2 = 18,
        local3 = 19,
        local4 = 20,
        local5 = 21,
        local6 = 22,
        local7 = 23,
    }

    public class Message
    {
        private int facility;
        private int level;
        private string text;

        // Get and set the facility
        public int Facility
        {
            get { return facility; }
            set { facility = value; }
        }

        // Get and set the level
        public int Level
        {
            get { return level; }
            set { level = value; }
        }

        // Get and set the text
        public string Text
        {
            get { return text; }
            set { text = value; }
        }

        // Message constructor
        public Message(int facility, int level, string text)
        {
            this.facility = facility;
            this.level = level;
            this.text = text;
        }
    }

    public class UdpClient : System.Net.Sockets.UdpClient
    {
        public UdpClient() : base() { }
        public UdpClient(IPEndPoint ipe) : base(ipe) { }
        ~UdpClient()
        {
            if (this.Active) this.Close();
        }

        public bool isActive
        {
            get { return this.Active; }
        }
    }


    public class Client
    {
        private SyslogClient.UdpClient udpClient;
        private string _sysLogServerIp = null;
        private int _port = 514;

        public Client()
        {
            udpClient = new SyslogClient.UdpClient();
        }

        public bool isActive
        {
            get { return udpClient.isActive; }
        }

        public void Close()
        {
            if (udpClient.isActive) udpClient.Close();
        }

        public int Port
        {
            set { _port = value; }
            get { return _port; }
        }

        public string SysLogServerIp
        {
            get { return _sysLogServerIp; }
            set
            {
                if ((_sysLogServerIp == null) && (!isActive))
                {
                    _sysLogServerIp = value;
                    //udpClient.Connect(_hostIp, _port);
                }
            }
        }

        public void Send(SyslogClient.Message message)
        {
            if (!udpClient.isActive) {
                IPAddress ip = IPAddress.Parse(_sysLogServerIp);
                IPEndPoint ipEndPoint = new IPEndPoint(ip, _port);
                udpClient.Connect(ipEndPoint); 
            }
            if (udpClient.isActive)
            {
                int priority = message.Facility * 8 + message.Level;
                string msg = System.String.Format("<{0}>{1}",
                                                  priority,
                                                  message.Text);
                byte[] bytes = System.Text.Encoding.ASCII.GetBytes(msg);
                udpClient.Send(bytes, bytes.Length);
            }
            else throw new Exception("Syslog Client Socket is not connected. Please check the Syslog Server IP property.");
        }

    }
}