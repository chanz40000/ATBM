package TH3_Socket;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.StringTokenizer;

public class Server {
    public static void main(String[] args) throws Exception {
        int port = 2000;
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("waiting for client!");

        while (true){
            Socket socket = serverSocket.accept();
                   System.out.println("ket noi thanh cong");
            new Process(socket).run();
        }

    }
//    private static void loginPro(BufferedReader br, PrintWriter pw) throws IOException {
//        String line = "";
//        StringTokenizer tokenizer;
//        System.out.println("User Login");
//        while (true){
//            String uname = "";
//            line = br.readLine();
//            tokenizer = new StringTokenizer(line);
//            uname = tokenizer.nextToken();
//        }
//
//
//    }
}
