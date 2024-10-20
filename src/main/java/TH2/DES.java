package TH2;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DES {
    private SecretKey key;
    public void loadKey(SecretKey key){
        this.key=key;
    }

    public SecretKey genKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        key=keyGenerator.generateKey();
        return key;
    }

    public byte[]encrypt(String text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, this.key);
        byte[] data = text.getBytes();
        ByteArrayInputStream input = new ByteArrayInputStream(data);
        CipherInputStream in = new CipherInputStream(input, cipher);
        int i;
        byte[]read = new byte[1024];
        byte[]re = null;
        while ((i=in.read(read))!=-1){
            re = expand(re, read, i);
        }
        input.close();
        in.close();
        return re;
    }

    public String decrypt(byte[]text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, this.key);
        ByteArrayInputStream input = new ByteArrayInputStream(text);
        CipherInputStream in = new CipherInputStream(input, cipher);
        int i;
        byte[]read = new byte[1024];
        byte[]re = new byte[0];
        while ((i = in.read(read))!=-1){
            re = expand(re, read, i);
        }
        in.close();
        input.close();
        return new String(re);
    }
    private byte[]expand(byte[]data, byte[]expand, int limit){
        if(data==null){
            byte[]out = new byte[limit];
            System.arraycopy(expand, 0, out, 0, limit);
            return out;
        }
        byte[]out = new byte[data.length+ limit];
        System.arraycopy(data, 0, out, 0, data.length);
        System.arraycopy(expand, 0, out, data.length, limit);
        return out;

    }
    public String encryptBase64(String text) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException {
        return Base64.getEncoder().encodeToString(encrypt(text));
    }

//    public boolean encryptFile(String src, String des) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException{
//        Cipher cipher = Cipher.getInstance("DES");
//        cipher.init(Cipher.ENCRYPT_MODE, key);
//        BufferedInputStream bis = null;
//        try {
//            bis = new BufferedInputStream(new FileInputStream(src));
//            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(des));
//            CipherInputStream cis = new CipherInputStream(bis, cipher);
//            int i;
//            byte[]read =new byte[1024];
//            while ((i=cis.read(read))!=-1){
//                bos.write(read, 0, i);
//            }
//
//            cis.close();
//            bis.close();
//            bos.close();
//            return true;
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//
//
//    }
//    public boolean decryptFile(String src, String des) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException{
//        Cipher cipher = Cipher.getInstance("DES");
//        cipher.init(Cipher.DECRYPT_MODE, key);
//        BufferedInputStream bis = null;
//        try {
//            bis = new BufferedInputStream(new FileInputStream(src));
//            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(des));
//            CipherOutputStream cos = new CipherOutputStream(bos, cipher);
//            int i;
//            byte[]read =new byte[1024];
//            while ((i=bis.read(read))!=-1){
//                cos.write(read, 0, i);
//            }
//            cos.flush(); // Đảm bảo ghi tất cả dữ liệu ra tệp
//            cos.close();
//            bis.close();
//            bos.close();
//            return true;
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//
//
//    }
public boolean encryptFile(String src, String des) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
    Cipher cipher = Cipher.getInstance("DES");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    try (
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(src));
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(des));
            CipherOutputStream cos = new CipherOutputStream(bos, cipher) // Sử dụng CipherOutputStream để mã hóa
    ) {
        int i;
        byte[] read = new byte[1024];
        while ((i = bis.read(read)) != -1) {
            cos.write(read, 0, i); // Ghi dữ liệu vào CipherOutputStream
        }
        cos.flush(); // Đảm bảo ghi tất cả dữ liệu ra tệp
        return true;
    } catch (IOException e) {
        throw new RuntimeException(e);
    }
}

    public boolean decryptFile(String src, String des) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        try (
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(src));
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(des));
                CipherInputStream cis = new CipherInputStream(bis, cipher) // Sử dụng CipherInputStream để giải mã
        ) {
            int i;
            byte[] read = new byte[1024];
            while ((i = cis.read(read)) != -1) {
                bos.write(read, 0, i); // Ghi dữ liệu giải mã vào tệp đích
            }
            bos.flush(); // Đảm bảo ghi tất cả dữ liệu ra tệp
            return true;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException {
        DES des = new DES();
        des.genKey();
//        String text = "hello chang dayyy hehe";
//        System.out.println("text: "+ text);

//        byte[]array = des.encrypt(text);
//        System.out.println("encrypt: "+ new String(array));
//        System.out.println("decrypt: "+ des.decrypt(array));
        String src = "C://Users//ADMIN//Pictures//#bts.jpg";
        String dess = "C://Users//ADMIN//Pictures//#bts2.jpg";
        String src2 = "C://Users//ADMIN//Pictures//#bts3.jpg";
        boolean result = des.encryptFile(src, dess);
        System.out.println(result);
        boolean result2 = des.decryptFile(dess, src2);
        System.out.println(result2);
    }

}
