using System;
using System.Numerics;
using System.Security.Cryptography;


namespace VerifyIdentityProject.Platforms.Android
{
    //Innehåller domain parameters för BrainpoolP384r1 och kommer användas för:
    //*Mappning-funktionen senare i protokollet.
    //*Beräkning av public key punkten från private key.
    //*Alla elliptiska kurv-operationer
    public class EcdhMapping
    {
        // BrainpoolP384r1 domain parameters
        //P (Prime modulus) - Det primtal som definierar fältets storlek
        public static readonly byte[] P = StringToByteArray(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123" +
            "ACD3A729901D1A71874700133107EC53");

        //A och B - Koefficienter som definierar kurvans form (y² = x³ + ax + b)
        public static readonly byte[] A = StringToByteArray(
            "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F" +
            "8AA5814A503AD4EB04A8C7DD22CE2826");

        public static readonly byte[] B = StringToByteArray(
            "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D5" +
            "7CB4390295DBC9943AB78696FA504C11");

        //G_X och G_Y - X och Y koordinaterna för generatorpunkten G
        public static readonly byte[] G_X = StringToByteArray(
            "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8" +
            "E826E03436D646AAEF87B2E247D4AF1E");

        public static readonly byte[] G_Y = StringToByteArray(
            "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280" +
            "E4646217791811142820341263C5315");
        //Order - Ordningen av generatorpunkten
        public static readonly byte[] Order = StringToByteArray(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7" +
            "CF3AB6AF6B7FC3103B883202E9046565");
        public static (byte[] publicKeyX, byte[] publicKeyY) CalculatePublicKey(byte[] privateKey)
        {
            // Konvertera alla värden till positiva BigInteger
            BigInteger d = new BigInteger(privateKey.Reverse().Concat(new byte[] { 0 }).ToArray());
            BigInteger p = new BigInteger(P.Reverse().Concat(new byte[] { 0 }).ToArray());
            BigInteger a = new BigInteger(A.Reverse().Concat(new byte[] { 0 }).ToArray());
            BigInteger gx = new BigInteger(G_X.Reverse().Concat(new byte[] { 0 }).ToArray());
            BigInteger gy = new BigInteger(G_Y.Reverse().Concat(new byte[] { 0 }).ToArray());

            Console.WriteLine($"Private key as BigInteger: {d}");
            Console.WriteLine($"Modulus p: {p}");

            // Säkerställ att private key är inom rätt intervall
            d = ((d % (p - 1)) + (p - 1)) % (p - 1) + 1;

            Console.WriteLine($"Adjusted private key: {d}");

            // Point multiplication med modulär aritmetik
            BigInteger resultX = gx;
            BigInteger resultY = gy;
            BigInteger tempD = d;
            while (tempD > 0)
            {
                if ((tempD & 1) == 1)  // Kolla minst signifikanta bit
                {
                    (resultX, resultY) = PointAdd(resultX, resultY, gx, gy, p);
                }
                (gx, gy) = PointDouble(gx, gy, a, p);
                tempD = tempD >> 1;    // Bit shift höger
            }

            // Säkerställ positiva resultat inom modulus
            resultX = ((resultX % p) + p) % p;
            resultY = ((resultY % p) + p) % p;

            // Konvertera till byte arrays med rätt längd och ordning
            byte[] publicKeyX = ToFixedLengthByteArray(resultX, 48);
            byte[] publicKeyY = ToFixedLengthByteArray(resultY, 48);

            return (publicKeyX, publicKeyY);
        }

        private static byte[] ToFixedLengthByteArray(BigInteger value, int length)
        {
            byte[] bytes = value.ToByteArray().Reverse().ToArray();
            byte[] result = new byte[length];

            if (bytes.Length >= length)
            {
                Array.Copy(bytes, bytes.Length - length, result, 0, length);
            }
            else
            {
                Array.Copy(bytes, 0, result, length - bytes.Length, bytes.Length);
            }

            return result;
        }

        private static byte[] PadOrTruncate(byte[] input, int targetLength)
        {
            if (input.Length == targetLength) return input;

            byte[] result = new byte[targetLength];
            if (input.Length < targetLength)
            {
                Array.Copy(input, 0, result, targetLength - input.Length, input.Length);
            }
            else
            {
                Array.Copy(input, input.Length - targetLength, result, 0, targetLength);
            }
            return result;
        }

        // Hjälpmetoder för elliptisk kurv-aritmetik
        private static (BigInteger x, BigInteger y) PointDouble(BigInteger x, BigInteger y, BigInteger a, BigInteger p)
        {
            if (y.IsZero)
                return (BigInteger.Zero, BigInteger.Zero);

            BigInteger lambda = ((3 * x * x + a) * ModInverse(2 * y, p)) % p;
            BigInteger newX = (lambda * lambda - 2 * x) % p;
            BigInteger newY = (lambda * (x - newX) - y) % p;

            return (((newX % p) + p) % p, ((newY % p) + p) % p);
        }

        private static (BigInteger x, BigInteger y) PointAdd(BigInteger x1, BigInteger y1,
                                                           BigInteger x2, BigInteger y2, BigInteger p)
        {
            if (x1.IsZero && y1.IsZero) return (x2, y2);
            if (x2.IsZero && y2.IsZero) return (x1, y1);

            BigInteger lambda;
            if (x1 == x2 && y1 == y2)
                return PointDouble(x1, y1, p, p);

            lambda = ((y2 - y1) * ModInverse((x2 - x1 + p) % p, p)) % p;
            BigInteger newX = (lambda * lambda - x1 - x2) % p;
            BigInteger newY = (lambda * (x1 - newX) - y1) % p;

            return (((newX % p) + p) % p, ((newY % p) + p) % p);
        }

     

        private static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            if (m == 1) return 0;

            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            return (x + m0) % m0;
        }

        // Hjälpmetod för att konvertera byte array till BigInteger
        public static BigInteger ToBigInteger(byte[] bytes)
        {
            // Skapa en kopia av bytes med ett extra byte för att säkerställa positivt tal
            byte[] paddedBytes = new byte[bytes.Length + 1];
            Array.Copy(bytes, 0, paddedBytes, 0, bytes.Length);
            paddedBytes[bytes.Length] = 0; // Lägg till en extra 0-byte i slutet

            // Vänd byte-ordningen för att hantera big-endian format
            Array.Reverse(paddedBytes);

            return new BigInteger(paddedBytes);
        }

        // Parsar en hex-sträng till en byte-array
        private static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
