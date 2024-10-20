package TH1;


import javax.crypto.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class EncryptFile {
    public static String fileToBase64(String nameFile){
        try {
            byte[]fileBytes = Files.readAllBytes(new File(nameFile).toPath());
            return Base64.getEncoder().encodeToString(fileBytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[]encrypt(String data, Key secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher =Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data.getBytes());
    }
    public static void saveEncryptData(byte[]encryptData, String outputFilePath){
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath);
            fileOutputStream.write(encryptData);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String fileEncrypt = "C://Users//ADMIN//Downloads//text.txt";
        String fileToBase64 = fileToBase64(fileEncrypt);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        byte[]encryptData = encrypt(fileToBase64, secretKey);

        String outFile = "C://Users//ADMIN//Downloads//text2.txt";
        saveEncryptData(encryptData, outFile);
        System.out.println("da ma hoa file");
    }
}
