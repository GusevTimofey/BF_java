package Encrypt;

import java.io.*;

class FileClass {
    private byte[] txtByte;
    private BlowFish bf = new BlowFish("qwertyqwertyqwertyqwertyqwertyqwerty");

    FileClass() throws UnsupportedEncodingException {
    }

    void workWithFiles() throws IOException {
        File inputDataFile = new File("D:\\222", "Безымянный.png");
        File outputEncryptedFile = new File("D:\\222","encryptedData.png");
        File outputDecryptedFile = new File("D:\\222","outputData.png");

        FileInputStream fileInputStream;
        FileOutputStream fileOutputStream;

        System.out.println("Длинна файла на входе: " + inputDataFile.length());
        try {
            fileInputStream = new FileInputStream(inputDataFile);
            txtByte = new byte[(int) inputDataFile.length()];
            fileInputStream.read(txtByte);
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] tmp1 = bf.encryptBlock64(txtByte);

        try {
            fileOutputStream = new FileOutputStream(outputEncryptedFile);
            fileOutputStream.write(tmp1, 0, tmp1.length);
            fileOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Длинна шифрованного файла на выходе из цикла шифрования: " + outputDecryptedFile.length());

        try {
            fileInputStream = new FileInputStream(outputEncryptedFile);
            txtByte = new byte[(int) outputEncryptedFile.length()];
            fileInputStream.read(txtByte);
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] tmp2 = bf.decryptBlock64(txtByte);

        try {
            fileOutputStream = new FileOutputStream(outputDecryptedFile);
            fileOutputStream.write(tmp2, 0, tmp2.length);
            fileOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Длинна рассшифрованного файла на выходе из цикла дешифрования: " + outputDecryptedFile.length());
    }
}