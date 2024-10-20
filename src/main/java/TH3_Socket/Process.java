package TH3_Socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;

public class Process extends Thread{
    Socket socket;
    BufferedReader netIn;
    PrintWriter netOut;
    Boolean pass = false;
    Boolean user=false;

    SecretKey secretKey;
    IvParameterSpec iv;

    public Process(Socket socket) throws Exception {
        this.socket = socket;
        generateKeyAndIV();
        Cipher cipherIn = Cipher.getInstance("AES/CTR/NoPadding");
        cipherIn.init(Cipher.DECRYPT_MODE, secretKey, iv);

        Cipher cipherOut = Cipher.getInstance("AES/CTR/NoPadding");
        cipherOut.init(Cipher.ENCRYPT_MODE, secretKey, iv);

         netIn = new BufferedReader(new InputStreamReader(new CipherInputStream(socket.getInputStream(), cipherIn)));
         netOut = new PrintWriter(new CipherOutputStream(socket.getOutputStream(), cipherOut));

    }
    public void run(){
        netOut.println("Hello, welcome to my server!!");
        netOut.flush();
        String request, respond;
        try {
        while (true){
                request = netIn.readLine();
                if(request.equalsIgnoreCase("EXIT"))break;

                if(request.contains("uname")){
                    String[]array = request.split(" ");
                    if(array[1].equals("admin")){
                        user=true;
                        netOut.println("vui long nhap password");
                        netOut.flush();
                    }else {
                        user=false;
                        netOut.println("nguoi dung khong ton tai");
                        netOut.flush();
                    }
                }else
            if(request.contains("pass")){
                if(user){
                    String[]array = request.split(" ");
                    if(array[1].equals("123")){
                        pass = true;
                        netOut.println("Login thanh cong, muon lam gi thi lam");
                        netOut.flush();
                    }else {
                        pass = false;
                        netOut.println("mat khau khong dung, vui long nhap lai");
                        netOut.flush();
                    }
                }else{
                    netOut.println("vui long nhap ten user");
                    netOut.flush();
                }

            }else{
                if(user&pass){
                    respond = "client: "+request;
                    netOut.println(respond);
                    netOut.flush();
                }else{
                    netOut.println("sai cu phap");
                    netOut.flush();
                }
            }


        }
            netOut.println("BYE");
            netOut.flush();
        netIn.close();
        netOut.close();
        socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    private void generateKeyAndIV() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);  // Khóa 128-bit
        secretKey = keyGen.generateKey();  // Tạo khóa bí mật AES

        byte[] ivBytes = new byte[16];  // IV phải có độ dài 16 byte
        SecureRandom random = new SecureRandom();  // Tạo đối tượng SecureRandom
        random.nextBytes(ivBytes);  // Tạo ngẫu nhiên IV
        iv = new IvParameterSpec(ivBytes);  // Khởi tạo IvParameterSpec với IV đã tạo

        // Sử dụng try-with-resources để đảm bảo các luồng ghi được đóng đúng cách
        try (FileOutputStream fos = new FileOutputStream("key_iv.dat");
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(secretKey);  // Ghi SecretKey vào file
            oos.writeObject(Base64.getEncoder().encodeToString(iv.getIV()));  // Ghi IV dưới dạng Base64
            System.out.println("Secret key and IV saved to key_iv.dat");
        } catch (IOException e) {
            System.err.println("Error while writing key and IV to file: " + e.getMessage());
        }
    }

}
