
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.Sockets;
using System.Net;
using System.IO;



namespace csSniffer
{
   
    public enum Protocol//id of a protocol in a packet packet
    {
        ICMP = 1,
        TCP = 6,
        UDP = 17,        
        Unknown = -1
    }
    
    public partial class Window : Form
    {
        public static void CatchFunction(Exception ex)
        {
            StreamWriter Strw;
            FileInfo Errors = new FileInfo(Directory.GetCurrentDirectory() + @"\Errors.txt");
            if (!Errors.Exists)
                Strw = new StreamWriter(Errors.Create(), System.Text.Encoding.UTF8);
            else
                Strw = Errors.AppendText();
            Strw.WriteLine("\r\n*Errors logging at: {0}*", DateTime.Now);
            Strw.WriteLine("Message: " + ex.Message + "; source: " + ex.Source + "; data: " + ex.Data + "; stacktrace: "+ex.StackTrace);
            Strw.Flush();
            MessageBox.Show("An error has occured: " + ex.Message + ". For more information see the Errors.txt logs.");
            
        }
        StreamWriter SmWr;
        private Socket socket;//Socket that will be sniffered
        private byte[] buffer;//Buffer to store all the information
        public Window()
        {
            try
            {
                InitializeComponent();
                this.AutoSize = true;
                this.AutoSizeMode = AutoSizeMode.GrowAndShrink;
                this.ControlBox = false;
                FileInfo Logs = new FileInfo(Directory.GetCurrentDirectory() + @"\Logs.txt");
                if (Logs.Exists)
                    Logs.Delete();
                SmWr = new StreamWriter(Logs.Create(), Encoding.UTF8);
                string HostName = Dns.GetHostName();
                IPHostEntry HosyEntry = Dns.GetHostEntry(HostName);// Dns servise 
                if (HosyEntry.AddressList.Length > 0)
                {
                    foreach (IPAddress ip in HosyEntry.AddressList)
                    {
                        if( ip.AddressFamily == AddressFamily.InterNetwork)
                            comboBox1.Items.Add(ip.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                CatchFunction(ex);
            }

        }
        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = socket.EndReceive(ar);
                Print(buffer, nReceived);
                buffer = new byte[4096];
                socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None,
                    OnReceive, null);
            }
            catch (Exception ex)
            {
                //CatchFunction(ex);
            }

        }
        void Print(byte[] buf, int len)
        {
            try
            {
                csSniffer.DataStructures.IPHeader ipHeader = new csSniffer.DataStructures.IPHeader(buf, len);
                bool UDP = checkBox3.Checked;
                bool TCP = checkBox3.Checked;
                if ((ipHeader.ProtocolType == Protocol.UDP && UDP == true) || (ipHeader.ProtocolType == Protocol.TCP && TCP == true) || (ipHeader.ProtocolType == Protocol.ICMP))
                {
                    string temp = string.Empty;
                    for (int i = 0; i < len; i++)
                    {
                        temp += buf[i].ToString("X2") + "  ";
                        if ((i + 1) % 16 == 0 && i != 0)
                        {
                            //string txt = Encoding.ASCII.GetString(buf, i, 16);
                            temp += "\r\n";
                        }
                        else { }

                    }
                    richTextBox1.BeginInvoke(new Action(() => richTextBox1.AppendText("\r\n\r\n\r\n" + "[---------------------------Raw data---------------------------]\r\n" + temp + "\r\n" + Parse(buf, len) + " \r\n")));
                    SmWr.WriteLine("\r\n\r\n\r\n" + "[---------------------------Raw data---------------------------]\r\n" + temp + "\r\n" + Parse(buf, len) + " \r\n");
                    SmWr.Flush();
                }
            }
            catch (Exception ex)
            {
                //CatchFunction(ex);
            }
        }

        public string Parse(byte[] buf, int len)
        {
            try
            {
                csSniffer.DataStructures.IPHeader ipHeader = new csSniffer.DataStructures.IPHeader(buf, len);
                string IpHeader = "\r\n[---------------------------New packet---------------------------]\r\n" +
                                    "--IP header: " +
                                     "-Version: " + ipHeader.Version +
                                     "\r\n-IP Header length: " + ipHeader.HeaderLength +
                                     "\r\n-TOS: " + ipHeader.DifferentiatedServices +
                                     "\r\n-Total length: " + ipHeader.TotalLength +
                    "\r\n-Identification: " + ipHeader.Identification +
                    "\r\n-Flags: " + ipHeader.Flags +
                    "\r\n-Fragmentation: " + ipHeader.FragmentationOffset +
                    "\r\n-TTL: " + ipHeader.TTL +
                    "\r\n-Protocol: " + ipHeader.ProtocolType +
                    "\r\n-Header checksum: " + ipHeader.Checksum +
                    "\r\n-Source address: " + ipHeader.SourceAddress +
                    "\r\n-Destination address: " + ipHeader.DestinationAddress;
                    
                if (ipHeader.ProtocolType == Protocol.TCP)
                {
                    csSniffer.DataStructures.TCPHeader tcpHeader = new csSniffer.DataStructures.TCPHeader(ipHeader.Data, len - Convert.ToInt32(ipHeader.HeaderLength));
                    IpHeader += "\r\n\r\n--TCP header: " +
                        "\r\n-Source port: " + tcpHeader.usSourcePort +
                        "\r\n-Destination port: " + tcpHeader.usDestinationPort +
                        "\r\n-Sequence number: " + tcpHeader.uiSequenceNumber +
                        "\r\n-Acknowledge number: " + tcpHeader.uiAcknowledgeNumber +
                        "\r\n-Offset & space & flag: " + tcpHeader.usOffsetSpaceFlag +
                        "\r\n-Window: " + tcpHeader.usWindow +
                        "\r\n-Checksum: " + tcpHeader.usChecksum.ToString("X2").ToLower() +
                        "\r\n-Urgent pointer: " + tcpHeader.usUrgentPointer;
                }
                if (ipHeader.ProtocolType == Protocol.UDP)
                {
                    csSniffer.DataStructures.UDPHeader udpHeader = new csSniffer.DataStructures.UDPHeader(ipHeader.Data, len - Convert.ToInt32(ipHeader.HeaderLength));
                    IpHeader += "\r\n\r\n--UDP header: " +
                        "\r\n-Source port: " + udpHeader.usSourcePort +
                        "\r\n-Destination port: " + udpHeader.usDestinationPort +
                        "\r\n-Datagram length: " + udpHeader.usLength +
                        "\r\n-Checksum: " + udpHeader.usCheckSum.ToString("X2").ToLower();                        
                }
                if (ipHeader.ProtocolType == Protocol.ICMP)
                {
                    csSniffer.DataStructures.ICMPHeader udpHeader = new csSniffer.DataStructures.ICMPHeader(ipHeader.Data, len - Convert.ToInt32(ipHeader.HeaderLength));
                    IpHeader += "\r\n\r\n--ICMP header: " +
                        "\r\n-Type: " + udpHeader.Type +
                        "\r\n-Status: " + udpHeader.Serial +
                        "\r\n-Checksum: " + udpHeader.usCheckSum.ToString("X2").ToLower();
                }
                return IpHeader;

            }
            catch (Exception ex)
            {
                //CatchFunction(ex);
                return "";
            }
        }
        

       
      

        /// <summary>
        /// /////////////
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
      

      

        private void saveFileDialog1_FileOk(object sender, CancelEventArgs e)
        {
            // Get file name.
            string name = saveFileDialog1.FileName;
            // Write to the file name selected.
            // ... You can write the text from a TextBox instead of a string literal.
            File.WriteAllText(name, richTextBox1.Text);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            richTextBox1.Clear();
        }

        private void button2_Click_1(object sender, EventArgs e)
        {
            
        }

        private void button3_Click(object sender, EventArgs e)
        {
            saveFileDialog1.ShowDialog();
        }

        private void comboBox1_SelectedIndexChanged_1(object sender, EventArgs e)
        {

        }

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {

        }

        private void checkBox3_CheckedChanged(object sender, EventArgs e)
        {

        }

        private void Window_Load(object sender, EventArgs e)
        {

        }

        private void button4_Click(object sender, EventArgs e)
        {
            CloseProg();
        }

        public void CloseProg()
        {
            MessageBox.Show("*Thank you for the sniffer usage* (Written by Dzianis Leanenka, BSUIR, 2016)");
            SmWr.Close();
            SmWr.Dispose();
            this.Close();
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            try
            {
                if ((sender as CheckBox).Checked)
                {
                    try
                    {
                        (sender as CheckBox).Text = "Stop Capturing";
                        socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);// creation of a new socket
                        socket.Bind(new IPEndPoint(IPAddress.Parse(comboBox1.SelectedItem.ToString()), 0)); // bind the socket with the chosen IP-address
                        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                    }
                    catch (Exception ex)
                    {
                        CatchFunction(ex);
                    }
                    byte[] byInc = new byte[] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4];
                    buffer = new byte[4096];//buffer for receiving data
                    socket.IOControl(IOControlCode.ReceiveAll, byInc, byOut);// promiscuous mode
                    socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, OnReceive, null);// start receiving packets in asynchronous mode; buffer,size,socketFlags,callback,state

                }
                else
                {
                    socket.Close();
                    (sender as CheckBox).Text = "Start capturing";
                }
            }
            catch (Exception ex)
            {
                //CatchFunction(ex);
            }
        }

        private void saveFileDialog1_FileOk_1(object sender, CancelEventArgs e)
        {
            // Get file name.
            string name = saveFileDialog1.FileName;
            // Write to the file name selected.
            // ... You can write the text from a TextBox instead of a string literal.
            File.WriteAllText(name, richTextBox1.Text);
        }
    }   
        
}


