using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
namespace ConsoleApplication1
{
    public class Play
    {
        public static void Main(string [] args)
        {
            Encrypter.EncryptText(@"Data Source=KABYLAKE\HIEPNGUYEN;Initial Catalog=Flower;Integrated Security=True");
            string salt1 = Encrypter.Salt;
            string pass1 = Encrypter.PassWord;
            Console.WriteLine("Salt: " + salt1);
            Console.WriteLine("Pass: " + pass1);
            Console.ReadLine();
            Console.Read();
            Console.ReadKey();


        }
    }
}
