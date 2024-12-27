package javaD.demo.service;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.*;
import java.security.Security;
import java.util.Iterator;

@RestController
public class PGPFileDecryptor {

	
	/*
	 * 
	 * 
	 * 
	 * https://youritmate.us/pgp/
	 * 
	 * using this website generate public and private key and put password   to generate encrypted file... 
	 * use this encrypted file for decryption 
	 */
	
	
	@GetMapping("/decrypt")
    public void rumMethod() throws Exception {
        System.out.println("Working Directory: " + System.getProperty("user.dir"));

        // Paths to the encrypted PGP file, private key, and output file
        String encryptedFile = "encrypted_file.pgp";
        String privateKeyFile = "private_key.asc";
        String outputFile = "decrypted_output.csv";
        String passphrase = "Raj145119";

        // Construct absolute paths based on the working directory
        String absoluteEncryptedFile = System.getProperty("user.dir") + File.separator + encryptedFile;
        String absolutePrivateKeyFile = System.getProperty("user.dir") + File.separator + privateKeyFile;
        String absoluteOutputFile = System.getProperty("user.dir") + File.separator + outputFile;
       // System.out.println("absoluteEncryptedFile=="+absoluteEncryptedFile+"absolutePrivateKeyFile=="+absolutePrivateKeyFile+"absoluteOutputFile=="+absoluteOutputFile);
        decryptPGPFile(absoluteEncryptedFile, absolutePrivateKeyFile, passphrase, absoluteOutputFile);
    }

    public void decryptPGPFile(String encryptedFile, String privateKeyFile, String passphrase, String outputFile) throws Exception {
        // Initialize Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        // Open the encrypted PGP file
        FileInputStream encryptedStream = new FileInputStream(encryptedFile);
        InputStream decoderStream = PGPUtil.getDecoderStream(encryptedStream);
        PGPObjectFactory pgpFactory = new JcaPGPObjectFactory(decoderStream);

        // Read the encrypted data packet
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) pgpFactory.nextObject();
        PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataList.get(0);

        // Find the private key to decrypt the data
        FileInputStream privateKeyStream = new FileInputStream(privateKeyFile);
        InputStream decoderPrivateKeyStream = PGPUtil.getDecoderStream(privateKeyStream);
        PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(decoderPrivateKeyStream, new JcaKeyFingerprintCalculator());

        PGPSecretKey pgpSecretKey = null;

        // Iterate through each key ring and find the appropriate secret key 
        outerLoop:
        for (Iterator<PGPSecretKeyRing> it = pgpSecretKeyRingCollection.getKeyRings(); it.hasNext(); ) {
            Object keyRingObj = it.next();
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingObj;
            System.out.println("keyRing --------"+keyRing);
            for (Iterator<PGPSecretKey> iter = keyRing.getSecretKeys(); iter.hasNext(); ) {
                Object keyObj = iter.next();
                PGPSecretKey key = (PGPSecretKey) keyObj;
                System.out.println("............"+key.getKeyID()+"..............."+encryptedData.getKeyID()+"..............."+key.isSigningKey());
                if (key.isSigningKey() && key.getKeyID() == encryptedData.getKeyID()) {
                    pgpSecretKey = key;
                    break outerLoop;
                }
            }
        }

        if (pgpSecretKey == null) {
            throw new PGPException("Secret key for message not found.");
        }

        // Create a JCE based secret key decryptor
        PBESecretKeyDecryptor pbeSecretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder().build(passphrase.toCharArray());
        PGPPrivateKey privateKey = pgpSecretKey.extractPrivateKey(pbeSecretKeyDecryptor);

        // Decrypt the data
        InputStream decryptedStream = encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
        byte[] decryptedBytes = Streams.readAll(decryptedStream);

        


			        // Write decrypted data to output file
			        FileOutputStream outputFileStream = new FileOutputStream(outputFile);
			        //System.out.println(".......==>"+decryptedBytes[0]);
			        
			       
			        outputFileStream.write(decryptedBytes);
			        outputFileStream.close();
			
			        System.out.println("Decryption successful. Output written to: " + outputFile);
          
          
         
        
//        String decryptedData = new String(decryptedBytes, "UTF-8");
//        // Process decrypted data to skip headers or metadata
//        int startIndex = decryptedData.indexOf("\"\"\"BAN\"\"\",\"\"\"Migration date\"\"\"");
//        if (startIndex == -1) {
//            throw new PGPException("CSV header not found in decrypted data.");
//        }
//
//        // Write decrypted CSV data to output file
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
//            writer.write(decryptedData.substring(startIndex));
//        }
 

        System.out.println("Decryption successful. Output written to: " + outputFile);
    }

}