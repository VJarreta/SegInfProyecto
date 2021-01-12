import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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

    public static void bucle() {
        Double time20k = 0.0, time100k = 0.0, time200k = 0.0;
        int nTimes = 100;
        try{
            Security.addProvider(new BouncyCastleProvider());
            String file ="src/main/resources/files/20k";

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

            file ="src/main/resources/files/Key256bits";
            reader = new DataInputStream(new FileInputStream(file));
            byte[] keyBytes = new byte[reader.available()];
            reader.read(keyBytes);

            // Define Key + Cipher
            SecretKeySpec key = new SecretKeySpec(keyBytes, "RC4");

            Cipher cipher = Cipher.getInstance("RC4",BouncyCastleProvider.PROVIDER_NAME);

            int j = 10;
            while(j>0){
                byte[] cipherText = new byte[input20k.length];
                cipher.init(Cipher.ENCRYPT_MODE, key);
                int ctLength = cipher.update(input20k, 0, input20k.length, cipherText, 0);
                ctLength += cipher.doFinal(cipherText, ctLength);

                // decryption pass
                byte[] plainText = new byte[ctLength];
                cipher.init(Cipher.DECRYPT_MODE, key);
                int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
                ptLength += cipher.doFinal(plainText, ptLength);
                j--;
            }

            for(int i=0; i<nTimes; i++){
                //20kB:

                // encryption pass

                byte[] cipherText = new byte[input20k.length];
                cipher.init(Cipher.ENCRYPT_MODE, key);
                Timestamp t20k1 = new Timestamp(System.nanoTime());
                int ctLength = cipher.update(input20k, 0, input20k.length, cipherText, 0);
                ctLength += cipher.doFinal(cipherText, ctLength);
                Timestamp t20k2 = new Timestamp(System.nanoTime());

                time20k += (t20k2.getTime() - t20k1.getTime())/1000;

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

                time100k += (t100k2.getTime() - t100k1.getTime())/1000;

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


                time200k += (t200k2.getTime() - t200k1.getTime())/1000;

                // decryption pass

                plainText = new byte[ctLength];
                cipher.init(Cipher.DECRYPT_MODE, key);
                ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
                ptLength += cipher.doFinal(plainText, ptLength);
                input = new String(input200k);
                output = new String(plainText);

                assertEquals(input, output);
            }

            time20k /= nTimes;
            time100k /= nTimes;
            time200k /= nTimes;

            System.out.println("Algorithm: " + cipher.getAlgorithm() + ", Provider: " + cipher.getProvider().getName());

            System.out.println("Time with 20k: " + time20k);
            System.out.println("Time with 100k: " + time100k);
            System.out.println("Time with 200k: " + time200k);

        }catch(Exception e){
            e.printStackTrace();
        }


    }


    public static void main(String[] args) {
        bucle();
    }
}
