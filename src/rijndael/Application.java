package rijndael;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Assignment 2 COMP3260
 * Main executable class
 * @author prouast (c3220501), PNorth (c3148112)
 */
public class Application {

    /**
     * Main method for this assignment.
     * - Read inputs: Plaintext and key from selected input file and Ciphertext
     *  and key from selected input file.
     * - Call the respective methods from Rijndael.java
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        Scanner console = new Scanner(System.in); // Takes system input
        String plaintextEncryption = "";
        String keyEncryption = "";
        String ciphertextDecryption = "";
        String keyDecryption = "";
        int choice; // int for navigating menu
        Rijndael rj = new Rijndael();// instantiates The assignment class
        String File; // holds the console input 

        System.out.println("Select and enter");
        System.out.println("1 - Encrypt ( With Avalanche )");
        System.out.println("2 - Decrypt");
        System.out.println("9 - exit");
        choice = console.nextInt();
        
            switch(choice) {
                
                case 1: System.out.println ("Please enter file path" );// This menu choice handles encryption and avalanche

                    try {
                        System.out.println("\n\nFile: ");
                        File = console.next ();

                        Scanner scannerEncryption = new Scanner(new File(File)); // Opens the file specified by the user
                        scannerEncryption.useDelimiter(System.getProperty("line.separator"));
                    
                        plaintextEncryption = scannerEncryption.next();
                        keyEncryption = scannerEncryption.next();
                    
                        rj.assignmentEncryption(plaintextEncryption, keyEncryption);
                        System.out.println ("Your Output has been saved to the root folder as output_encryption.dat file");
                    } catch (FileNotFoundException ex) {
                        System.out.println ("The file was not found");
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }
                
                    break;

                case 2: System.out.println (" Please enter the address Of the File" ); // this handles decryption

                    try {
                        System.out.println("\n\nFile: ");
                        File = console.next ();
                    
                        Scanner scannerDecryption = new Scanner(new File(File));
                        scannerDecryption.useDelimiter(System.getProperty("line.separator"));
                    
                        ciphertextDecryption = scannerDecryption.next();
                        keyDecryption = scannerDecryption.next();
                    
                        rj.assignmentDecryption(ciphertextDecryption, keyDecryption);
                        System.out.println ("Your Output has been saved to the root folder as output_decryption.dat file");
                    } catch (FileNotFoundException ex) {
                        System.out.println ("The file was not found");
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    
                    break;
                    
                case 9: System.exit(1);

            }
        }
    }
