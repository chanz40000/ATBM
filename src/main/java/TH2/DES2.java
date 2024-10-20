package TH2;

import javax.crypto.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DES2 {
    SecretKey key;
    public SecretKey genKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        key = keyGenerator.generateKey();
        return key;
    }
    public void loadKey(SecretKey key){
        this.key = key;
    }
    public byte[] encrypt(String text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, this.key);
        byte[] data = text.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        CipherInputStream in = new CipherInputStream(inputStream, cipher);
        int i;
        byte[] read = new byte[1024];
        byte[] re = new byte[0];
        while ((i = in.read(read))!=-1) {
            re = expand(re, read, i);
        }
        in.close();
        inputStream.close();
        return re;
    }
    private byte[] expand(byte[] data, byte[] expand, int limit) {
        if ( data == null) {
            byte[] out = new byte[limit];
            System.arraycopy(expand, 0, out, 0, limit);
            return out;
        }
        byte[] out  = new byte[data.length + limit];
        System.arraycopy(data, 0, out, 0, data.length);
        System.arraycopy(expand, 0, out, data.length, limit);
        return out;
    }
    public String encryptBase64(String text) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return Base64.getEncoder().encodeToString(encrypt(text));

    }
    public String decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, this.key);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        CipherInputStream in = new CipherInputStream(inputStream, cipher);
        int i;
        byte[] read = new byte[1024];
        byte[] re = new byte[0];
        while ((i = in.read(read))!=-1) {
            re = expand(re, read, i);
        }
        in.close();
        inputStream.close();
        return new String(re);

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String data = "hello chang dayyy hehe";
        DES2 des = new DES2();
        des.genKey();
        byte[] re = des.encrypt(data);
        System.out.println(new String(re));
        System.out.println(des.decrypt(re));
    }
}