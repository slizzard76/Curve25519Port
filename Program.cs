using System;

namespace Curve5519Port
{
    class Program
    {
        static void Main(string[] args)
        {
            Curve25519.GenerateAndTest(args[0]);
        }
    }
}
