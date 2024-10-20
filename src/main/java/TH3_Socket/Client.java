package TH3_Socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    private Key secretKey = null;
    IvParameterSpec iv;
    Socket socket = new Socket("localhost", 2000);
    BufferedReader netIn;
    BufferedReader console;
    PrintWriter netOut;

    public Client() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        loadKeyAndIV();
        Cipher cipherIn = Cipher.getInstance("AES/CTR/NoPadding");
        cipherIn.init(Cipher.DECRYPT_MODE, secretKey, iv);
        Cipher cipherOut = Cipher.getInstance("AES/CTR/NoPadding");
        cipherOut.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new CipherInputStream(socket.getInputStream(), cipherIn)));
        PrintWriter printWriter = new PrintWriter(new CipherOutputStream(socket.getOutputStream(), cipherOut), true);

        Scanner scanner = new Scanner(System.in);
        String line;
        while(true){
            line=scanner.nextLine();
            printWriter.println(line);
            printWriter.flush();

            String response = bufferedReader.readLine();
            System.out.println(response);
        }
        //netIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        //console = new BufferedReader(new InputStreamReader(System.in));
        //netOut = new PrintWriter(socket.getOutputStream());
    }
    public void run_main() throws IOException {
        String welcome = netIn.readLine();
        System.out.println(welcome);
        while (true){
            netOut.println(console.readLine());
            netOut.flush();
            String data = netIn.readLine();
            System.out.println(data);
            if(data.equalsIgnoreCase("BYE"))break;
        }
    }
    private void loadKeyAndIV(){
        try{
            FileInputStream fis = new FileInputStream("C://Users//ADMIN//eclipse-workspace//ATBM//src//main//java//TH3_Socket//key_iv.dat");
            ObjectInputStream ois = new ObjectInputStream(fis);
            secretKey = (SecretKey) ois.readObject();
            String ivBase64 = (String)ois.readObject();
            iv = new IvParameterSpec(Base64.getDecoder().decode(ivBase64));
            System.out.println("Secres key and IV loaded from key_iv.dat");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        new Client().run_main();
    }
}
