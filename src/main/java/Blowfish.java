import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.sql.Timestamp;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class Blowfish {
    public static byte[] blowfishEncrypt(byte[] plaintext, byte[] signingKey) {
        if (signingKey.length != 32) {
            throw new IllegalArgumentException("Key length must be 32 bytes");
        }
        try {
            //for (int i = 0; i < 32; i++) {
            //    signingKey[i] ^= nonce[i];
            //}
            //byte[] key = getSha256().digest(signingKey);
            byte[] iv = new byte[8];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            PaddedBufferedBlockCipher blowfish = new PaddedBufferedBlockCipher(new CBCBlockCipher(new BlowfishEngine()));
            CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(signingKey), iv);
            blowfish.init(true, ivAndKey);
            byte[] output = new byte[blowfish.getOutputSize(plaintext.length)];
            int ciphertextLength = blowfish.processBytes(plaintext, 0, plaintext.length, output, 0);
            ciphertextLength += blowfish.doFinal(output, ciphertextLength);
            byte[] result = new byte[iv.length + ciphertextLength];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(output, 0, result, iv.length, ciphertextLength);
            return result;
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static byte[] blowfishDecrypt(byte[] encrypted, byte[] signingKey) {
        if (signingKey.length != 32) {
            throw new IllegalArgumentException("Key length must be 32 bytes");
        }
        try {
            if (encrypted.length < 8 || encrypted.length % 8 != 0) {
                throw new InvalidCipherTextException("invalid ciphertext");
            }
            byte[] iv = Arrays.copyOfRange(encrypted, 0, 8);
            byte[] ciphertext = Arrays.copyOfRange(encrypted, 8, encrypted.length);
            //for (int i = 0; i < 32; i++) {
            //    signingKey[i] ^= nonce[i];
            //}
            //byte[] key = getSha256().digest(signingKey);
            PaddedBufferedBlockCipher blowfish = new PaddedBufferedBlockCipher(new CBCBlockCipher(new BlowfishEngine()));
            CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(signingKey), iv);
            blowfish.init(false, ivAndKey);
            byte[] output = new byte[blowfish.getOutputSize(ciphertext.length)];
            int plaintextLength = blowfish.processBytes(ciphertext, 0, ciphertext.length, output, 0);
            plaintextLength += blowfish.doFinal(output, plaintextLength);
            byte[] result = new byte[plaintextLength];
            System.arraycopy(output, 0, result, 0, result.length);
            return result;
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static void bucle() {
        Double time20k = 0.0, time100k = 0.0, time200k = 0.0;
        int nTimes = 1000;
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
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");



            //Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding", "BC");

            int j = 10;
            while(j>0){
                byte[] cipherText = new byte[input20k.length];
                cipherText = blowfishEncrypt(input20k,keyBytes);

                // decryption pass

                byte[] plainText = blowfishDecrypt(cipherText,keyBytes);

                j--;
            }

            Timestamp total1 = new Timestamp(System.nanoTime());
            for(int i=0; i<nTimes; i++){
                //20kB:

                // encryption pass

                byte[] cipherText = new byte[input20k.length];

                Timestamp t20k1 = new Timestamp(System.nanoTime());

                cipherText = blowfishEncrypt(input20k,keyBytes);

                Timestamp t20k2 = new Timestamp(System.nanoTime());

                time20k += (t20k2.getTime() - t20k1.getTime())/1000;

                // decryption pass

                byte[] plainText = blowfishDecrypt(cipherText,keyBytes);


                String input = new String(input20k);
                String output = new String(plainText);

                assertEquals(input, output);


                //100kB:

                // encryption pass

                Timestamp t100k1 = new Timestamp(System.nanoTime());

                cipherText = blowfishEncrypt(input100k,keyBytes);

                Timestamp t100k2 = new Timestamp(System.nanoTime());

                time100k += (t100k2.getTime() - t100k1.getTime())/1000;

                // decryption pass

                plainText = blowfishDecrypt(cipherText,keyBytes);

                input = new String(input100k);
                output = new String(plainText);

                assertEquals(input, output);


                //200kB:


                // encryption pass

                Timestamp t200k1 = new Timestamp(System.nanoTime());

                cipherText = blowfishEncrypt(input200k,keyBytes);

                Timestamp t200k2 = new Timestamp(System.nanoTime());


                time200k += (t200k2.getTime() - t200k1.getTime())/1000;

                // decryption pass
                plainText = blowfishDecrypt(cipherText,keyBytes);
                input = new String(input200k);
                output = new String(plainText);

                assertEquals(input, output);
            }
            Timestamp total2 = new Timestamp(System.nanoTime());

            time20k /= nTimes;
            time100k /= nTimes;
            time200k /= nTimes;

            System.out.println("Algorithm: Blowfish/CBC/PKCS7Padding, Provider: BC");

            System.out.println("Mean time with 20k: " + time20k + " us");
            System.out.println("Mean time with 100k: " + time100k + " us");
            System.out.println("Mean time with 200k: " + time200k + " us");
            System.out.println("Total time: " + (double)(total2.getTime()-total1.getTime())/1000000000 + " seconds");
            System.out.println("Number of executions: " + nTimes);

        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        bucle();
    }
}
