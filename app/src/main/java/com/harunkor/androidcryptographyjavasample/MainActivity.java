package com.harunkor.androidcryptographyjavasample;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.security.crypto.EncryptedFile;
import androidx.security.crypto.MasterKey;
import androidx.security.crypto.MasterKeys;

import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Log;
import android.widget.TextView;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private SecretKey secretKey;
    private TextView textView;
    private SecretKeySpec secretKeySpec;
    private byte[] key;
    private static String SECRET_KEY = "DEVELOPER";

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        textView = findViewById(R.id.resulttext);

        setChipherSecretKey("DGPAYS");

        setSignature("DGPAYS");

        messageDigestEncrypt("DGPAYS");

        writeEncryptFile();

        setConvertHMAC("DGPAYSSECRET","DGPAYS");


    }


    private void setChipherSecretKey(String message){
        try {
            KeyGenerator keygen= KeyGenerator.getInstance("AES");
            keygen.init(256);
            secretKey= keygen.generateKey();


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }finally {
            chipherEncrypt(message);
        }

    }

    private void chipherEncrypt(String text) {
        try {
            byte[] plainText = text.getBytes(StandardCharsets.UTF_8);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);
            byte[] cipherByteArray = cipher.doFinal(plainText);

            StringBuilder sb = new StringBuilder();
            for(int i=0;i<cipherByteArray.length;i++){
                sb.append((char) cipherByteArray[i]);
            }

            textView.append("Chipher------------ \n"+sb);

            chipherDecrypt(cipherByteArray);


        }catch (Exception e){

        }
    }

    private void chipherDecrypt(byte[] decryptText) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE,secretKey);
            byte[] chipherText = cipher.doFinal(decryptText);

            StringBuilder sb = new StringBuilder();
            for(int i=0;i<chipherText.length;i++){
                sb.append((char) chipherText[i]);
            }

            textView.append("\n"+sb+"\n -------------Chipher");


        }catch (Exception e){

        }

    }

    private void setSignature(String strMessage){
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048);
            KeyPair keyPair = keygen.generateKeyPair();

            byte[] messageByteArray = strMessage.getBytes(StandardCharsets.UTF_8);

            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(messageByteArray);
            byte[] signatureByteArray = signature.sign();

            verifySignature(signatureByteArray,messageByteArray,keyPair.getPublic());

        }catch (Exception e){

        }

    }

    private void verifySignature(byte[] signatureByteArray, byte[] message, PublicKey key){
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(key);
            signature.update(message);
            boolean result = signature.verify(signatureByteArray);

            textView.append("\n Signature----- "+String.valueOf(result)+"------Signature");
        }catch (Exception e){

        }

    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void messageDigestEncrypt(String text){
        try {

        String encryptStr = encryptMessageDigest(text,SECRET_KEY);
        textView.append("\n encryptMessageDigest : "+encryptStr);
        String decryptStr = decryptMessageDigest(encryptStr,SECRET_KEY);
        textView.append("\n decryptMessageDigest: "+decryptStr);

        }catch (Exception e){

        }
    }

  // MessageDigest start
    private void setSecretKeyForMessageDigest(String secretKey){
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            key = secretKey.getBytes(StandardCharsets.UTF_8);
            key = messageDigest.digest(key);
            key = Arrays.copyOf(key,16);
            secretKeySpec = new SecretKeySpec(key,"AES");
        }catch (Exception e){

        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private String encryptMessageDigest(String message, String secret){
        try {
            setSecretKeyForMessageDigest(secret);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        }catch (Exception e){
            return  e.getMessage();
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private String decryptMessageDigest(String data, String secret){
        try {
            setSecretKeyForMessageDigest(secret);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE,secretKeySpec);
            return  new String(cipher.doFinal(Base64.getDecoder().decode(data)));

        }catch (Exception e){
            return  e.getMessage();
        }
    }
//MessageDigest end

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void writeEncryptFile(){
        try {
            KeyGenParameterSpec keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC;
            String mainKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec);
            String file = "my_sensetive_data.txt";
            EncryptedFile encryptedFile = new EncryptedFile.Builder(
                    new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),file),this, mainKeyAlias,
                    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build();
            byte[] fileContent = "DGPAYS".getBytes(StandardCharsets.UTF_8);
            OutputStream outputStream = encryptedFile.openFileOutput();
            outputStream.write(fileContent);
            outputStream.flush();
            outputStream.close();

        }catch (Exception e){

        }finally {
            readDcryptFile();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void  readDcryptFile(){
        try {
            String file = "my_sensetive_data.txt";
            KeyGenParameterSpec keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC;
            String mainKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec);

            EncryptedFile encryptedFile = new EncryptedFile.Builder(
                    new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),file),this, mainKeyAlias,
                    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build();

            InputStream inputStream = encryptedFile.openFileInput();
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            int nextByte = inputStream.read();
            while (nextByte != -1){
                byteArrayOutputStream.write(nextByte);
                nextByte = inputStream.read();
            }


            byte[] plainText = byteArrayOutputStream.toByteArray();
            String text = new String(plainText);

            textView.append("\n readDcryptFile---- "+text+" ----readDcryptFile");

        }catch (Exception e){

        }


    }


    @RequiresApi(api = Build.VERSION_CODES.O)
    private void setConvertHMAC(String secret, String message){
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(),"HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            byte[] result = mac.doFinal(message.getBytes());
            String hash = Base64.getEncoder().encodeToString(result);


            textView.append("\n Mac-----"+hash);

            generateHMAC(secret,result);

        }catch (Exception e){

        }finally {

        }
    }

    private void generateHMAC(String secret , byte[] resultdata){
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(),"HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            byte[] result = mac.doFinal(resultdata);

            textView.append("\n"+result+" ------Mac");


        }catch (Exception e){
            Log.v("DGPAYS",e.getMessage());
        }


    }




}