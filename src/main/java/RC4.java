import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.security.Security;
import java.sql.Timestamp;

import static org.junit.Assert.assertEquals;

public class RC4 {

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

            KeyParameter key = new KeyParameter(keyBytes);
            RC4Engine rc4 = new RC4Engine();

            int j = 10;
            while(j>0){
                byte[] cipherText = new byte[input20k.length];
                rc4.init(true, key);
                rc4.processBytes(input20k, 0, input20k.length, cipherText, 0);

                // decryption pass
                byte[] plainText = new byte[input20k.length];
                rc4.init(false, key);
                rc4.processBytes(cipherText, 0, input20k.length, plainText, 0);
                j--;
            }

            Timestamp total1 = new Timestamp(System.nanoTime());
            for(int i=0; i<nTimes; i++){
                //20kB:

                // encryption pass

                byte[] cipherText = new byte[input20k.length];
                rc4.init(true, key);
                Timestamp t20k1 = new Timestamp(System.nanoTime());
                rc4.processBytes(input20k, 0, input20k.length, cipherText, 0);
                Timestamp t20k2 = new Timestamp(System.nanoTime());

                time20k += (t20k2.getTime() - t20k1.getTime())/1000;

                // decryption pass
                byte[] plainText = new byte[input20k.length];
                rc4.init(false, key);
                rc4.processBytes(cipherText, 0, input20k.length, plainText, 0);

                String input = new String(input20k);
                String output = new String(plainText);

                assertEquals(input, output);


                //100kB:

                // encryption pass

                cipherText = new byte[input100k.length];
                rc4.init(true, key);
                Timestamp t100k1 = new Timestamp(System.nanoTime());
               rc4.processBytes(input100k, 0, input100k.length, cipherText, 0);
                Timestamp t100k2 = new Timestamp(System.nanoTime());

                time100k += (t100k2.getTime() - t100k1.getTime())/1000;

                // decryption pass

                plainText = new byte[input100k.length];
                rc4.init(false, key);
                rc4.processBytes(cipherText, 0, input100k.length, plainText, 0);
                input = new String(input100k);
                output = new String(plainText);

                assertEquals(input, output);


                //200kB:


                // encryption pass

                cipherText = new byte[input200k.length];
                rc4.init(true, key);
                Timestamp t200k1 = new Timestamp(System.nanoTime());
                rc4.processBytes(input200k, 0, input200k.length, cipherText, 0);
                Timestamp t200k2 = new Timestamp(System.nanoTime());


                time200k += (t200k2.getTime() - t200k1.getTime())/1000;

                // decryption pass

                plainText = new byte[input200k.length];
                rc4.init(false, key);
                rc4.processBytes(cipherText, 0, input200k.length, plainText, 0);
                input = new String(input200k);
                output = new String(plainText);

                assertEquals(input, output);
            }
            Timestamp total2 = new Timestamp(System.nanoTime());


            file ="src/main/resources/files/50MB";
            reader = new DataInputStream(new FileInputStream(file));
            byte[] input50MB = new byte[reader.available()];
            reader.read(input50MB);

            byte[] cipherText = new byte[input50MB.length];
            rc4.init(true, key);
            Timestamp bigFile1 = new Timestamp(System.nanoTime());
            rc4.processBytes(input50MB, 0, input50MB.length, cipherText, 0);
            Timestamp bigFile2 = new Timestamp(System.nanoTime());

            long bigFileTime = (bigFile2.getTime() - bigFile1.getTime())/1000;


            time20k /= nTimes;
            time100k /= nTimes;
            time200k /= nTimes;

            System.out.println("Algorithm: " + rc4.getAlgorithmName() + ", Provider: BC");

            System.out.println("Mean time with 20k: " + time20k + " us");
            System.out.println("Mean time with 100k: " + time100k + " us");
            System.out.println("Mean time with 200k: " + time200k + " us");
            System.out.println("Total time: " + (double)(total2.getTime()-total1.getTime())/1000000000 + " seconds");
            System.out.println("Number of executions: " + nTimes);
            System.out.println("50MB File encrypted in: " + bigFileTime + " us");

        }catch(Exception e){
            e.printStackTrace();
        }


    }


    public static void main(String[] args) {
        bucle();
    }
}
