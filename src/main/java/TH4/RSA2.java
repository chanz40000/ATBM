package TH4;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA2 {
    KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;

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
    // Encrypt the file content with AES, encrypt AES key with RSA, and write both to the output file.
    public void encryptFile(File inputFile, File outputFile) throws Exception {
        // Generate a new AES key for file encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Using AES-256
        SecretKey secretKey = keyGen.generateKey();

        // Encrypt the AES key with RSA and encode it in Base64
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSecretKey = rsaCipher.doFinal(secretKey.getEncoded());

        // Write the encrypted AES key to the output file
        try (FileOutputStream fileOut = new FileOutputStream(outputFile)) {
            fileOut.write(Base64.getEncoder().encode(encryptedSecretKey));
            fileOut.write("\n".getBytes());

            // Encrypt the file data with AES
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            try (FileInputStream fileIn = new FileInputStream(inputFile);
                 CipherOutputStream cipherOut = new CipherOutputStream(fileOut, aesCipher)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fileIn.read(buffer)) != -1) {
                    cipherOut.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    // Decrypt the file by reading and decrypting the AES key, then using it to decrypt the file content.
    public void decryptFile(File encryptedFile, File decryptedOutputFile) throws Exception {
        // Read the encrypted AES key from the beginning of the file
        try (BufferedReader fileIn = new BufferedReader(new FileReader(encryptedFile))) {
            String encryptedKeyBase64 = fileIn.readLine();
            byte[] encryptedSecretKey = Base64.getDecoder().decode(encryptedKeyBase64);

            // Decrypt the AES key with RSA
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] secretKeyBytes = rsaCipher.doFinal(encryptedSecretKey);
            SecretKey originalSecretKey = new SecretKeySpec(secretKeyBytes, "AES");

            // Prepare AES decryption cipher (use same mode/padding as encryption)
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, originalSecretKey);

            // Skip over the encrypted AES key and start reading the encrypted content
            try (FileInputStream encryptedFileIn = new FileInputStream(encryptedFile);
                 BufferedWriter fileOut = new BufferedWriter(new FileWriter(decryptedOutputFile))) {

                // Skip the line containing the Base64 encrypted AES key
                encryptedFileIn.skip(encryptedKeyBase64.length() + 1);

                // Decrypt the file data using AES
                try (CipherInputStream cipherIn = new CipherInputStream(encryptedFileIn, aesCipher)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = cipherIn.read(buffer)) != -1) {
                        fileOut.write(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
                    }
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        String text = "C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//test.txt";
        String encryptFile = "C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//encryptFile.txt";
        String decryptFile = "C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//decryptFile.txt";
        RSA2 rsa2 = new RSA2();
        // Generate keys and save them to a file
        rsa2.genKey("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//key.txt");

        // Load keys from the file
        rsa2.loadKey("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH4//key.txt");
        rsa2.encryptFile(new File(text), new File(encryptFile));
        rsa2.decryptFile(new File(encryptFile), new File(decryptFile));
    }
}
