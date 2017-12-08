package Encrypt;

import javafx.fxml.FXML;
import javafx.scene.control.TextField;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class JavaFxClass extends Component {
    private byte[] txtByte;
    private byte[] byteInputKey;
    private SecureRandom random = new SecureRandom();

    @FXML
    private TextField UserKey;
    @FXML
    private TextField bottom1line3;
    @FXML
    private TextField bottom1field4;
    @FXML
    private TextField bottom1line5;
    @FXML
    private TextField bottom2line1;

    private void printLine1Bottom2(int[] arr) {
        bottom2line1.setText("Length of decipher data is: " + arr[0]);
    }

    private String readTextFromTextLineUnderBottomCipherOneFile() {
        return UserKey.getText();
    }

    private void printFirstBottomText(String string) {
        bottom1line3.setText("Length user's key is: " + string.length());
    }

    private void printFirstBottomField4(byte[] arr) {
        bottom1field4.setText("Length of input data is: " + arr.length);
    }

    private void printLine5(byte[] arr) {
        bottom1line5.setText("Length of cipher data is: " + arr.length);
    }

    private String genIV() {
        return new BigInteger(32, random).toString(16);
    }

    public void cipherOneFile() throws IOException {
        File inputOpenKey = new File("D:\\222\\BF_java\\BF_java", "OpenKey.txt");
        File inputExtensionFile = new File("D:\\222\\BF_java\\BF_java", "extensionFile.txt");
        File IvFile = new File("D:\\222\\BF_java\\BF_java", "IvFile.txt");

        FileInputStream fileInputStream;
        FileOutputStream fileOutputStream;
        JFileChooser fileChooser = new JFileChooser();

        //Get from user OpenKey
        try {
            if (!inputOpenKey.exists()) {
                try {
                    inputOpenKey.createNewFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            String openKeyString = readTextFromTextLineUnderBottomCipherOneFile();
            printFirstBottomText(openKeyString);
            byte[] openKeyBytes = openKeyString.getBytes();
            fileOutputStream = new FileOutputStream(inputOpenKey);
            fileOutputStream.write(openKeyBytes, 0, openKeyBytes.length);
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            fileInputStream = new FileInputStream(inputOpenKey);
            byteInputKey = new byte[(int) inputOpenKey.length()];
            fileInputStream.read(byteInputKey);
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        BlowFish bf = new BlowFish(byteInputKey);

        //Get file from user
        fileChooser.showOpenDialog(this);
        File inputDataFile = fileChooser.getSelectedFile();

        try {
            fileInputStream = new FileInputStream(inputDataFile);
            txtByte = new byte[(int) inputDataFile.length()];
            fileInputStream.read(txtByte);
            printFirstBottomField4(txtByte);
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }


        try {
            if (!IvFile.exists()) {
                try {
                    IvFile.createNewFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            String IV = genIV();
            byte[] byteIV;
            byteIV = IV.getBytes();
            fileOutputStream = new FileOutputStream(IvFile);
            fileOutputStream.write(byteIV, 0, byteIV.length);

        } catch (IOException e) {
            e.printStackTrace();
        }

        fileInputStream = new FileInputStream(IvFile);
        byte[] bytesIV = new byte[(int) IvFile.length()];
        fileInputStream.read(bytesIV);

        byte[] tmp1 = bf.encryptBlock64(txtByte, bytesIV);

        String fileName = fileChooser.getName(inputDataFile);
        int indexOf = fileName.lastIndexOf('.');
        String fileExtension = fileName.substring(indexOf, fileName.length());
        byte[] extensionBytes = fileExtension.getBytes();

        if (!inputExtensionFile.exists()) {
            try {
                inputExtensionFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            fileOutputStream = new FileOutputStream(inputExtensionFile);
            fileOutputStream.write(extensionBytes);
            fileOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            fileInputStream = new FileInputStream(inputExtensionFile);
            byte[] tmp = new byte[(int) inputExtensionFile.length()];
            printLine5(tmp1);
            fileInputStream.read(tmp);
            String extensionString = new String(tmp);
            fileOutputStream = new FileOutputStream("encryptedData" + extensionString);
            fileOutputStream.write(tmp1, 0, tmp1.length);
            fileOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void decipherOneFile() throws IOException {
        File inputExtensionFile = new File("D:\\222\\BF_java\\BF_java", "extensionFile.txt");
        File inputOpenKey = new File("D:\\222\\BF_java\\BF_java", "OpenKey.txt");
        File IvFile = new File("D:\\222\\BF_java\\BF_java", "IvFile.txt");

        FileInputStream fileInputStream;
        FileOutputStream fileOutputStream;
        JFileChooser fileChooser = new JFileChooser();

        try {
            fileInputStream = new FileInputStream(inputOpenKey);
            byteInputKey = new byte[(int) inputOpenKey.length()];
            fileInputStream.read(byteInputKey);
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        BlowFish bf = new BlowFish(byteInputKey);

        fileChooser.showOpenDialog(this);
        File inputDataFile = fileChooser.getSelectedFile();

        try {
            fileInputStream = new FileInputStream(inputDataFile);
            txtByte = new byte[(int) inputDataFile.length()];
            fileInputStream.read(txtByte);
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        fileInputStream = new FileInputStream(IvFile);
        byte[] bytesIV = new byte[(int) IvFile.length()];
        fileInputStream.read(bytesIV);

        byte[] tmp1 = bf.decryptBlock64(txtByte, bytesIV);

        try {
            fileInputStream = new FileInputStream(inputExtensionFile);
            byte[] tmp = new byte[(int) inputExtensionFile.length()];
            fileInputStream.read(tmp);
            fileInputStream.close();

            String extensionString = new String(tmp);
            fileOutputStream = new FileOutputStream("decryptedData" + extensionString);

            byte[] tmp3 = new byte[tmp1.length - 8];
            System.arraycopy(tmp1, 8, tmp3, 0, tmp3.length);

            byte[] arrTmp1 = new byte[4];
            System.arraycopy(tmp1,0,arrTmp1,0,4);
            int[] k;
            k = byte2int(arrTmp1);

            printLine1Bottom2(k);
            fileOutputStream.write(tmp3, 0, k[0]);
            fileOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private int[] byte2int(byte[] bytesArray) {
        int[] byte2int = new int[bytesArray.length / 4];
        int offset = 0;

        for (int i = 0; i < byte2int.length; ++i)
            byte2int[i] = bytesArray[3 + offset] & 255 | (bytesArray[2 + offset] & 255) << 8 | (bytesArray[1 + offset] & 255) << 16 | (bytesArray[offset] & 255) << 24;
            offset += 4;

        return byte2int;
    }
}
