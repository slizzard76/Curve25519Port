using System;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Security;

using SimpleBase;
using NPOI.POIFS.Crypt;
using System.Text;

public class Curve25519
{

    private readonly static char[] hexArray = "0123456789abcdef".ToCharArray();
    private readonly static string ENCRYPTION_IV = "1a2b3c4d5e6f7g8h";
       
    private static string Encrypt(string src, string key)
    {
        try
        {
            Cipher cipher = Cipher.GetInstance("AES/CBC/PKCS5Padding");
            cipher.Init(Cipher.ENCRYPT_MODE, MakeKey(key), MakeIv());
            return Base58.Bitcoin.Encode(cipher.DoFinal(Encoding.UTF8.GetBytes(src)));
        }
        catch (Exception e)
        {
            Console.WriteLine(e.StackTrace);
        }
        return null;
    }

    private static string Decrypt(string src, string key)
    {
        string decrypted = "";
        try
        {
            Cipher cipher = Cipher.GetInstance("AES/CBC/PKCS5Padding");
            cipher.Init(Cipher.DECRYPT_MODE, MakeKey(key), MakeIv());
            var c = cipher.DoFinal(Base58.Bitcoin.Decode(src).ToArray());
            decrypted = Encoding.UTF8.GetString(c);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.StackTrace);
        }
        return decrypted;
    }

    private static AlgorithmParameterSpec MakeIv()
    {
        try
        {
            return new IvParameterSpec(Encoding.UTF8.GetBytes(ENCRYPTION_IV));
        }
        catch (Exception e)
        {
            Console.WriteLine(e.StackTrace);
        }
        return null;
    }

    private static IKey MakeKey(string encryptionKey)
    {
        try
        {
            byte[] key;
            using (var sha256 = SHA256.Create())
            {
                key = sha256.ComputeHash(Encoding.UTF8.GetBytes(encryptionKey));
            }
            return new SecretKeySpec(key, "AES");
        }
        catch (Exception e)
        {
            Console.WriteLine(e.StackTrace);
        }
        return null;
    }

    private static string BytesToHex(byte[] bytes)
    {
        char[] hexChars = new char[bytes.Length * 2];
        for (int j = 0; j < bytes.Length; j++)
        {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new string(hexChars);
    }

    private static byte[] SavePublicKey(AsymmetricKeyParameter key)
    {
        ECPublicKeyParameters eckey = (ECPublicKeyParameters)key;
        return eckey.Q.GetEncoded();
    }

    private static AsymmetricKeyParameter LoadPublicKey(byte[] data)
    {
        X9ECParameters ecP = CustomNamedCurves.GetByName("curve25519");
        ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(ecSpec.Curve.DecodePoint(data), ecSpec);
        return pubKey;
    }

    private static byte[] SavePrivateKey(AsymmetricKeyParameter key)
    {
        ECPrivateKeyParameters eckey = (ECPrivateKeyParameters)key;
        return eckey.D.ToByteArray();
    }

    public static AsymmetricKeyParameter LoadPrivateKey(byte[] data)
    {
        X9ECParameters ecP = CustomNamedCurves.GetByName("curve25519");
        ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
        ECPrivateKeyParameters prvkey = new ECPrivateKeyParameters(new Org.BouncyCastle.Math.BigInteger(data), ecSpec);
        return prvkey;
    }

    private static string DoECDH(byte[] dataPrv, byte[] dataPub)
    {
        IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("ECDH");
        agreement.Init(LoadPrivateKey(dataPrv));
        Org.BouncyCastle.Math.BigInteger sharedSecret = agreement.CalculateAgreement(LoadPublicKey(dataPub));
        byte[] secret = sharedSecret.ToByteArray();
        return BytesToHex(secret);
    }

    public static string EncryptData(string data, string privateKey, string publicKey)
    {
        AsymmetricKeyParameter PrivateKey = LoadPrivateKey(Hex.Decode(privateKey));
        AsymmetricKeyParameter PublicKey = LoadPublicKey(Hex.Decode(publicKey));
        byte[] dataPrvA = SavePrivateKey(PrivateKey);
        byte[] dataPubB = SavePublicKey(PublicKey);

        Console.WriteLine("*************************************Encryption********************************");
        Console.WriteLine("Private Key : " + BytesToHex(dataPrvA));
        Console.WriteLine("Public Key : " + BytesToHex(dataPubB));

        string secret = DoECDH(dataPrvA, dataPubB);
        Console.WriteLine("secret: " + secret);
        string encrypted = Encrypt(data, secret);
        return encrypted;
    }

    public static string DecryptData(string encrypted, string privateKey, string publicKey)
    {
        AsymmetricKeyParameter PrivateKey = LoadPrivateKey(Hex.Decode(privateKey));
        AsymmetricKeyParameter PublicKey = LoadPublicKey(Hex.Decode(publicKey));

        byte[] dataPrvA = SavePrivateKey(PrivateKey);
        byte[] dataPubB = SavePublicKey(PublicKey);

        Console.WriteLine("*************************************Decryption********************************");
        Console.WriteLine("Private Key : " + BytesToHex(dataPrvA));
        Console.WriteLine("Public Key : " + BytesToHex(dataPubB));
        string secret = DoECDH(dataPrvA, dataPubB);

        Console.WriteLine("secret: " + secret);

        string decrypted = Decrypt(encrypted, secret);

        return decrypted;
    }

    public static string Sign(string encrypted, string pvtKey)
    {
        ISigner signer = SignerUtilities.GetSigner("SHA256withECDSA");
        AsymmetricKeyParameter privateKey = LoadPrivateKey(Hex.Decode(pvtKey));
        signer.Init(true, privateKey);
        signer.BlockUpdate(Encoding.UTF8.GetBytes(encrypted), 0, Encoding.UTF8.GetBytes(encrypted).Length);
        byte[] signatureBytes = signer.GenerateSignature();
        string signatures = BytesToHex(signatureBytes);
        return signatures;
    }

    public static bool IsSignCorrect(string encrypted, string signatures, string pubKey)
    {
        ISigner signer = SignerUtilities.GetSigner("SHA256withECDSA");
        AsymmetricKeyParameter PublicKey = LoadPublicKey(Hex.Decode(pubKey));
        signer.Init(false, PublicKey);
        signer.BlockUpdate(Encoding.UTF8.GetBytes(encrypted), 0, Encoding.UTF8.GetBytes(encrypted).Length);
        bool isSigned = signer.VerifySignature(Hex.Decode(signatures));
        return isSigned;
    }

    public static void GenerateAndTest(string dataToCrypt)
    {
    /******* Generating keys **********/
        X9ECParameters ecP = CustomNamedCurves.GetByName("curve25519");
        ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
        IAsymmetricCipherKeyPairGenerator kpgen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
        kpgen.Init(new ECKeyGenerationParameters(ecSpec, new SecureRandom()));
        AsymmetricCipherKeyPair pairA = kpgen.GenerateKeyPair();
        AsymmetricCipherKeyPair pairB = kpgen.GenerateKeyPair();
        var PrivateA = pairA.Private;
        var PublicA = pairA.Public;
        var PrivateB = pairB.Private;
        var PublicB = pairB.Public;
        string privateA = new string(BytesToHex(SavePrivateKey(PrivateA)));
        string publicA = new string(BytesToHex(SavePublicKey(PublicA)));

        string privateB = new string(BytesToHex(SavePrivateKey(PrivateB)));
        string publicB = new string(BytesToHex(SavePublicKey(PublicB)));

        Console.WriteLine("PrvA: " + privateA);
        Console.WriteLine("PubA: " + publicA);
        Console.WriteLine("PrvB: " + privateB);
        Console.WriteLine("PubB: " + publicB);
            /********* Encrypt and decrypt with signature ***********/
        string encrypted = EncryptData(dataToCrypt, privateB, publicA);
        Console.WriteLine("Encrypted : " + encrypted);
        string sign = Sign(encrypted, privateB);
        Console.WriteLine("signature : " + sign);
        bool isSignedCorrect = IsSignCorrect(encrypted, sign, publicB);
        Console.WriteLine("Signature is OK ? " + isSignedCorrect);
        if (isSignedCorrect)
        {
            string decrypted = DecryptData(encrypted, privateA, publicB);
            Console.WriteLine("Is OK " + decrypted.Equals(dataToCrypt));
            Console.WriteLine("decrypted Data : " + decrypted);
        }
        else
        {
            Console.WriteLine("Signature not valid");
        }
    }
}

