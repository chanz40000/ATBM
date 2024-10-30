package TH4;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {
    KeyPair keyPair;
    PrivateKey privateKey;
    PublicKey publicKey;
    SecretKey secretKey;
    IvParameterSpec iv;

    public RSA() throws Exception {
        generateKeyAndIV();
    }



    public byte[] encrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] in = data.getBytes(StandardCharsets.UTF_8);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(in);
    }

    public String encryptBase64(String data) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return Base64.getEncoder().encodeToString(encrypt(data));
    }
    public String decrypt(String base64) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] in = Base64.getDecoder().decode(base64);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] out = cipher.doFinal(in);
        return new String(out, StandardCharsets.UTF_8);
    }
    public  byte[] decrypt2(String base64) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] in = Base64.getDecoder().decode(base64);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] out = cipher.doFinal(in);
        return out;
    }
public void encryptFile() throws Exception {
    FileInputStream fis = new FileInputStream(new File("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//test.txt"));
    DataOutputStream dos = new DataOutputStream(new FileOutputStream(new File("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//encryptFile.txt")));

    SecretKey secretKey1 = generateKey();
    // Mã hóa secretKey
    byte[] encryptedKeyBytes = encrypt(Base64.getEncoder().encodeToString(secretKey1.getEncoded()));

    // Lưu độ dài của khóa đã mã hóa
    dos.writeInt(encryptedKeyBytes.length); // Ghi độ dài khóa
    dos.write(encryptedKeyBytes); // Ghi khóa đã mã hóa

    // Mã hóa nội dung file
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey1); // Sử dụng secretKey để mã hóa

    CipherOutputStream cipherOutputStream = new CipherOutputStream(dos, cipher);

    byte[] buffer = new byte[4096];
    int bytesRead;
    while ((bytesRead = fis.read(buffer)) != -1) {
        cipherOutputStream.write(buffer, 0, bytesRead);
    }

    // Đóng các luồng
    cipherOutputStream.close(); // Đảm bảo dòng mã hóa được đóng
    fis.close();
    dos.close();

    System.out.println("Đã mã hóa file thành công");
}

    public SecretKey decryptSecretKey(byte[] encryptedKeyBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKeyBytes);

        return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
    }

    public void decryptFile() throws Exception {
        DataInputStream dis = new DataInputStream(new FileInputStream(new File("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//encryptFile.txt")));
        FileOutputStream decryptedFileOutputStream = new FileOutputStream(new File("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//decryptedFile.txt"));

        // Đọc độ dài của khóa đã mã hóa
        int keyLength = dis.readInt(); // Đảm bảo độ dài được ghi chính xác
        byte[] encryptedKeyBytes = new byte[keyLength];
        dis.readFully(encryptedKeyBytes); // Đọc khóa đã mã hóa

        // Giải mã khóa bí mật sử dụng RSA
        SecretKey originalSecretKey = decryptSecretKey(encryptedKeyBytes);

        // Khởi tạo cipher AES với khóa bí mật đã giải mã
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, originalSecretKey);

        // Giải mã nội dung file
        CipherInputStream cipherInputStream = new CipherInputStream(dis, cipher);
        byte[] buffer = new byte[4096];
        int bytesRead;

        while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
            decryptedFileOutputStream.write(buffer, 0, bytesRead);
        }

        // Đóng các luồng
        cipherInputStream.close(); // Đóng CipherInputStream trước
        decryptedFileOutputStream.close();
        dis.close();

        System.out.println("File đã được giải mã thành công.");
    }

    public SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Có thể là 128, 192, hoặc 256
        SecretKey secretKey = keyGen.generateKey();
        // In ra độ dài khóa sau khi tạo
        System.out.println("Độ dài khóa AES: " + secretKey.getEncoded().length * 8 + " bits");

        return secretKey;
    }


    // Modified genKey method to save keys as Base64-encoded strings in a text file
    public void genKey(String address) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
//        publicKey = keyPair.getPublic();
//        privateKey = keyPair.getPrivate();

        // Encode the keys in Base64 and save to file
        try (FileWriter writer = new FileWriter(address)) {
            writer.write("PublicKey=" + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()) + "\n");
            writer.write("PrivateKey=" + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()) + "\n");
        }

    }

    // Modified loadKey method to load keys from a Base64-encoded text file
    public void loadKey(String address) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(address));
        String publicKeyString = reader.readLine().split("=")[1];
        String privateKeyString = reader.readLine().split("=")[1];
        reader.close();

        // Decode the Base64 strings and generate PublicKey and PrivateKey objects
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        privateKey = keyFactory.generatePrivate(privateKeySpec);
    }
    public void generateKeyAndIV()throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        secretKey = keyGenerator.generateKey();
        byte[]ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
    }

    public static void main(String[] args) throws Exception {
        RSA rsa = new RSA();

        // Generate keys and save them to a file
        rsa.genKey("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//key.txt");

        // Load keys from the file
        rsa.loadKey("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//key.txt");

        // Test encryption and decryption
        String encryptedData = rsa.encryptBase64("LOP DH21DTD");
        System.out.println("Encrypted: " + encryptedData);
        System.out.println("Decrypted: " + rsa.decrypt(encryptedData));
        rsa.encryptFile();
        rsa.decryptFile();
    }
}
