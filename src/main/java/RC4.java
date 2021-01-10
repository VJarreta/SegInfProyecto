import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.sql.Timestamp;
import org.apache.commons.codec.binary.Base64;


import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.symmetric.ARC4;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64Encoder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class RC4 {

    public static byte[] rc4encrypt(byte[] msg, byte[] key) {

        RC4Engine inCipher = new RC4Engine();
        inCipher.init(true, new KeyParameter(key));
        byte[] outcipher = new byte[msg.length];
        inCipher.processBytes(msg, 0, msg.length, outcipher, 0);

        return outcipher;
    }

    public static byte[] rc4decrypt(byte[] msg, byte[] key) {

        RC4Engine inCipher = new RC4Engine();
        inCipher.init(false, new KeyParameter(key));
        byte[] outcipher = new byte[msg.length];

        inCipher.processBytes(msg,0,msg.length, outcipher, 0);
        return outcipher;
    }


    public static void main(String[] args) {
        try{
            Security.addProvider(new BouncyCastleProvider());
            String file ="src/main/resources/files/20k";
            String result = null;
            RC4Engine rc4Engine = new RC4Engine();
            RC4Engine decrypter = new RC4Engine();

            DataInputStream reader = new DataInputStream(new FileInputStream(file));
            byte[] input20k = new byte[reader.available()];
            reader.read(input20k);

            file ="src/main/resources/files/100k";
            reader = new DataInputStream(new FileInputStream(file));
            byte[] input100k = new byte[reader.available()];
            reader.read(input100k);

            file ="src/main/resources/files/200k";
            reader = new DataInputStream(new FileInputStream(file));
            byte[] input200k = new byte[reader.available()];
            reader.read(input200k);

            file ="src/main/resources/files/Key256";
            reader = new DataInputStream(new FileInputStream(file));
            byte[] keyBytes = new byte[reader.available()];
            reader.read(keyBytes);

            //Outputs:
            byte[] output20k = new byte[input20k.length];
            byte[] output100k = new byte[input100k.length];
            byte[] output200k = new byte[input200k.length];

            // Define Key + Cipher
            SecretKeySpec key = new SecretKeySpec(keyBytes, "RC4");

            Cipher cipher = Cipher.getInstance("RC4",BouncyCastleProvider.PROVIDER_NAME);

            //20kB:

            // encryption pass

            byte[] cipherText = new byte[input20k.length];

            cipher.init(Cipher.ENCRYPT_MODE, key);

            Timestamp t20k1 = new Timestamp(System.nanoTime());

            int ctLength = cipher.update(input20k, 0, input20k.length, cipherText, 0);

            ctLength += cipher.doFinal(cipherText, ctLength);

            Timestamp t20k2 = new Timestamp(System.nanoTime());


            System.out.println("RC4 With 20KB: " + (t20k2.getTime() - t20k1.getTime())/1000 + (" us"));

            // decryption pass

            byte[] plainText = new byte[ctLength];

            cipher.init(Cipher.DECRYPT_MODE, key);

            int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);

            ptLength += cipher.doFinal(plainText, ptLength);

            String input = new String(input20k);
            String output = new String(plainText);

            assertEquals(input, output);


            //100kB:


            // encryption pass

            cipherText = new byte[input100k.length];

            cipher.init(Cipher.ENCRYPT_MODE, key);

            Timestamp t100k1 = new Timestamp(System.nanoTime());

            ctLength = cipher.update(input100k, 0, input100k.length, cipherText, 0);

            ctLength += cipher.doFinal(cipherText, ctLength);

            Timestamp t100k2 = new Timestamp(System.nanoTime());


            System.out.println("RC4 With 100KB: " + (t100k2.getTime() - t100k1.getTime())/1000 + (" us"));

            // decryption pass

            plainText = new byte[ctLength];

            cipher.init(Cipher.DECRYPT_MODE, key);

            ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);

            ptLength += cipher.doFinal(plainText, ptLength);

            input = new String(input100k);
            output = new String(plainText);

            assertEquals(input, output);



            //200kB:


            // encryption pass

            cipherText = new byte[input200k.length];

            cipher.init(Cipher.ENCRYPT_MODE, key);

            Timestamp t200k1 = new Timestamp(System.nanoTime());

            ctLength = cipher.update(input200k, 0, input200k.length, cipherText, 0);

            ctLength += cipher.doFinal(cipherText, ctLength);

            Timestamp t200k2 = new Timestamp(System.nanoTime());


            System.out.println("RC4 With 200KB: " + (t200k2.getTime() - t200k1.getTime())/1000 + (" us"));

            // decryption pass

            plainText = new byte[ctLength];

            cipher.init(Cipher.DECRYPT_MODE, key);

            ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);

            ptLength += cipher.doFinal(plainText, ptLength);

            input = new String(input200k);
            output = new String(plainText);

            assertEquals(input, output);

            System.out.println("Algorithm: " + cipher.getAlgorithm() + ", Provider: " + cipher.getProvider().getName());

        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
