using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.Ports;
using System.Threading;

namespace ConsoleApp1
{
    public class PortChat
    {
        static bool flag;   //表示是否继续传输
        static SerialPort serialport;   // 串行端口
        public static void Main()
        {
            string name;
            string message;
            StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;   //进行字符串比较
            Thread readThread = new Thread(Read);
            serialport = new SerialPort();
            serialport.PortName = SetPortName(serialport.PortName); //设置参数
            serialport.Open();  //开启端口
            flag = true;
            readThread.Start();
            Console.Write("输入名称: ");
            name = Console.ReadLine();
            Console.WriteLine("输入“quit”以退出：");
            while (flag)    //可继续传输，传输数据
            {
                Console.WriteLine("输入传输数据：");
                message = Console.ReadLine();

                if (stringComparer.Equals("quit", message))
                {
                    flag = false;
                }
                else
                {
                    serialport.WriteLine(
                        String.Format("<{0}>: {1}", name, message));
                }
            }
            readThread.Join();
            serialport.Close();
        }
        public static void Read()
        {
            while (flag)
            {
                string message = serialport.ReadLine();
                Console.WriteLine(message);
            }
        }
        public static string SetPortName(string defaultPortName)    //设置端口
        {
            string portName;
            Console.WriteLine("查询可用端口:");
            foreach (string s in SerialPort.GetPortNames())
            {
                Console.WriteLine("     {0}", s);
            }
            Console.Write("输入端口(Default: COM1): ", defaultPortName);
            portName = Console.ReadLine();
            if (portName == "" || !(portName.ToLower()).StartsWith("com"))
            {
                portName = defaultPortName; //默认COM1
            }
            return portName;
        }
    }
}
