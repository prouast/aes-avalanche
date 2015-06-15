package rijndael ;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Rijndael implementation in Java
 * @author prouast Pnorth
 */
public class Rijndael {
    
    /* CONSTANTS */
    
    // Block dimensions
    static final int COLS = 4;
    static final int ROWS = 4;
    
    private static final int FIELD_SIZE = 256; // Field size of GF.
    private static final int IRREDUCIBLE_POLYNOMIAL = 283; // Irr. polynomial
    
    // S-box copied from http://en.wikipedia.org/wiki/Rijndael_S-box
    private static final char S[] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    
    // Inverse S-box copied from http://en.wikipedia.org/wiki/Rijndael_S-box
    private static final char INV_S[] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };
    
    // Rcon constants copied from http://en.wikipedia.org/wiki/Rijndael_key_schedule
    private static final char RCON[] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    };
    
    // How are rows shifted in encryption
    // Worked these out on paper
    private static final byte[] SHIFT = {
        0, 5, 10, 15,
        4, 9, 14, 3,
        8, 13, 2, 7,
        12, 1, 6, 11
    };
    
    // How are rows shifted in decryption
    // Worked these out on paper
    private static final byte[] INV_SHIFT = {
        0, 13, 10, 7,
        4, 1, 14, 11,
        8, 5, 2, 15,
        12, 9, 6, 3
    };
    
    /* ALGORITHM */
    
    /**
     * AES Encryption.
     * Encrypt a given state, i.e., block of 16 bytes using a given key of
     * 16 bytes using the Rijndael algorithm
     * @param state plaintext state
     * @param key encryption key
     * @return ciphertext state
     */
    public byte[] encrypt(byte[] state, byte[] key) {
        
        // Expand the cipher key into 11 subkeys and prepare for usage
        byte[][] expandedKey = mapKey(expand(key));
        
        // Step 1: Add round key
        state = addRoundKey(state, expandedKey[0]);
        
        // Step 2: 9 main encryption rounds consisting of
        //  SubstituteBytes + ShiftRows + MixColumns + AddRoundKey
        for (int i = 1; i < 10; i++)
            state = addRoundKey(mixColumns(shiftRows(substituteBytes(state))), expandedKey[i]);
        
        // Last encryption round consisting of
        //  SubstituteBytes + ShiftRows + AddRoundKey
        state = addRoundKey(shiftRows(substituteBytes(state)), expandedKey[10]);
        
        return state;
    }
    
    /**
     * AES Decryption.
     * Decrypt a given state, i.e., block of 16 bytes using a given key of
     * 16 bytes using the Rijndael algorithm
     * @param state ciphertext state
     * @param key decryption key
     * @return plaintext state
     */
    public byte[] decrypt(byte[] state, byte[] key) {
        
        // Expand the cipher key into 11 subkeys and prepare for usage
        // Round keys are used from last to first in decryption.
        byte[][] expandedKey = mapKey(expand(key));
        
        // Step 1: Add last round key
        state = addRoundKey(state, expandedKey[10]);
        
        // Step 2: 9 main decryption rounds consisting of
        //  InvShiftRows + InvSubstituteBytes + AddRoundKey + InvMixColumns
        for (int i = 9; i > 0; i--)
            state = invMixColumns(addRoundKey(invSubstituteBytes(invShiftRows(state)), expandedKey[i]));
        
        // Last decryption round consisting of
        //  SubstituteBytes + ShiftRows + AddRoundKey
        state = addRoundKey(invSubstituteBytes(invShiftRows(state)), expandedKey[0]);
        
        return state;
    }
    
    /**
     * Composite method for different versions of the algorithm.
     * Called by assignmentEncryption.
     * @param state input state
     * @param key encryption key
     * @param round encryption round
     * @param type algorithm type (AES0, AES1,…)
     * @return modified state
     */
    public byte[] round(byte[] state, byte[] key, int round, int type) {
        
        byte[][] expandedKey = mapKey(expand(key));
        
        switch (round) {
            case 10: {
                if (type != 1) state = substituteBytes(state);
                if (type != 2) state = shiftRows(state);
                if (type != 4) state = addRoundKey(state, expandedKey[round]);
            } break;
            default: {
                if (type != 1) state = substituteBytes(state);
                if (type != 2) state = shiftRows(state);
                if (type != 3) state = mixColumns(state);
                if (type != 4) state = addRoundKey(state, expandedKey[round]);
            } break;
        }
        
        return state;
    }
    
    /* ASSIGNMENTS */
    
    /**
     * Method containing encryption and avalanche analysis.
     * As stated in task description. Save results to text files.
     * @param plaintext plaintext
     * @param key encryption key
     */
    public void assignmentEncryption(String plaintext, String key) {
        
        try {
            
            // Write output to this file
            PrintWriter out = new PrintWriter("output_encryption.txt");
            
            out.println("ENCRYPTION");
            out.println("Plaintext P:\t" + plaintext);
            out.println("Key K:\t\t" + key);
            
            // Convert states to byte[] format
            byte[] stateP = convertFromString(plaintext);
            byte[] stateK = convertFromString(key);
            
            // Assuming we only want to know the time for one run of AES algorithm
            long startTime = System.currentTimeMillis();
            byte[] stateC = encrypt(stateP, stateK); // Do regular encryption
            long endTime = System.currentTimeMillis();
            
            out.println("Ciphertext C:\t" + convertToString(stateC));
            out.println("Running time:\t" + (endTime-startTime) + " ms");
            
            // Avalanche
            out.println("Avalanche:");
            
            // 1. P under K and P_i under K
            out.println("P under K and P_i under K");
            out.println("Round\t\tAES0\t\tAES1\t\tAES2\t\tAES3\t\tAES4");
            
            // Arrays to store results
            int[][] distPunderKPiunderK = new int[5][128];
            byte[][][] statePiunderK = new byte[5][128][16]; // Store P_i under K
            byte[][] statePunderK = new byte[5][16]; // Store P under K
            
            // Prepare P_i under K
            for (byte[][] statePi1 : statePiunderK) {
                for (int j = 0; j < statePiunderK[0].length; j++) {
                    // Deep copy of Plaintext
                    System.arraycopy(stateP, 0, statePi1[j], 0, statePiunderK[0][0].length);
                    // Alter state
                    statePi1[j] = alteredState(statePi1[j], j);
                }
            }
            
            // Prepare P under K
            for (byte[] statePunderK1 : statePunderK) {
                // Deep copy of Plaintext
                System.arraycopy(stateP, 0, statePunderK1, 0, statePunderK[0].length);
            }
            
            // Round 0
            out.print("0\t\t");
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 128; j++) {
                    distPunderKPiunderK[i][j] = hammingDist(statePunderK[i], statePiunderK[i][j]); // Calculate hamming distance
                }
                out.print("" + average(distPunderKPiunderK[i]) + "\t\t"); // Print average distance
            }
            out.println();
            
            // AddRoundKey
            for (int i = 0; i < 5; i++) {
                statePunderK[i] = addRoundKey(statePunderK[i], stateK); // To P
                for (int j = 0; j < 128; j++) {
                    statePiunderK[i][j] = addRoundKey(statePiunderK[i][j], stateK); // To P_i
                }
            }
            
            // Round 1-10
            for (int i = 1; i < 11; i++) {
                out.print("" + i + "\t\t");
                for (int j = 0; j < 5; j++) {
                    statePunderK[j] = round(statePunderK[j], stateK, i, j); // Apply operations to P
                    for (int k = 0; k < 128; k++) {
                        statePiunderK[j][k] = round(statePiunderK[j][k], stateK, i, j); // Apply operations to P_i
                        distPunderKPiunderK[j][k] = hammingDist(statePunderK[j], statePiunderK[j][k]); // Calculate hamming distance
                    }
                    out.print("" + average(distPunderKPiunderK[j]) + "\t\t"); // Print average distance
                }
                out.println();
            }
            
            // 2. P under K and K_i
            out.println("P under K and P under K_i");
            out.println("Round\t\tAES0\t\tAES1\t\tAES2\t\tAES3\t\tAES4");
            
            // Arrays to store results
            int[][] distPunderKPunderKi = new int[5][128];
            byte[][][] statePunderKi = new byte[5][128][16]; // Store P under K_i
            byte[][] stateKi = new byte[128][16];
            
            // Reset P under K
            for (byte[] statePunderK1 : statePunderK) {
                // Deep copy of Plaintext
                System.arraycopy(stateP, 0, statePunderK1, 0, statePunderK[0].length);
            }
            
            // Prepare P under K_i
            for (byte[][] statePunderKi1 : statePunderKi) {
                for (int j = 0; j < statePunderKi[0].length; j++) {
                    // Deep copy of Plaintext
                    System.arraycopy(stateP, 0, statePunderKi1[j], 0, statePunderKi[0][0].length);
                }
            }
            
            // Prepare keys
            for (int i = 0; i < stateKi.length; i++) {
                // Deep copy of key
                System.arraycopy(stateK, 0, stateKi[i], 0, stateKi[0].length);
                // Alter key
                stateKi[i] = alteredState(stateKi[i], i);
            }
            
            // Round 0
            out.print("0\t\t");
            for (int i = 0; i < statePunderKi.length; i++) {
                for (int j = 0; j < statePunderKi[0].length; j++) {
                    distPunderKPunderKi[i][j] = hammingDist(statePunderK[i], statePunderKi[i][j]); // Calculate hamming distance
                }
                out.print("" + average(distPunderKPunderKi[i]) + "\t\t"); // Print average distance
            }
            out.println();
            
            // AddRoundKey
            for (int i = 0; i < 5; i++) {
                statePunderK[i] = addRoundKey(statePunderK[i], stateK);
                for (int j = 0; j < statePunderKi[0].length; j++) {
                    statePunderKi[i][j] = addRoundKey(statePunderKi[i][j], stateKi[j]);
                }
            }
            
            // Round 1-10
            for (int i = 1; i < 11; i++) {
                out.print("" + i + "\t\t");
                for (int j = 0; j < statePunderKi.length; j++) {
                    statePunderK[j] = round(statePunderK[j], stateK, i, j); // Apply operations to P under K
                    for (int k = 0; k < statePunderKi[0].length; k++) {
                        statePunderKi[j][k] = round(statePunderKi[j][k], stateKi[k], i, j); // Apply operations to P under K_i
                        distPunderKPunderKi[j][k] = hammingDist(statePunderK[j], statePunderKi[j][k]); // Calculate hamming distance
                    }
                    out.print("" + average(distPunderKPunderKi[j]) + "\t\t"); // Print average distance
                }
                out.println();
            }
            
            out.close();
            
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Rijndael.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Method containing decryption.
     * As stated in task description. Save results to text files.
     * @param ciphertext ciphertext
     * @param key decryption key
     */
    public void assignmentDecryption(String ciphertext, String key) {
        
        try {
            
            PrintWriter out = new PrintWriter("output_decryption.txt");
            
            // Encryption
            out.println("DECRYPTION");
            out.println("Ciphertext C:\t" + ciphertext);
            out.println("Key K:\t\t\t" + key);
            
            // Convert states to byte[] format
            byte[] stateC = convertFromString(ciphertext);
            byte[] stateK = convertFromString(key);
            
            // Assuming we only want to know the time for one run of AES algorithm
            long startTime = System.currentTimeMillis();
            byte[] stateP = decrypt(stateC, stateK); // Do regular decryption
            long endTime = System.currentTimeMillis();
            
            out.println("Plaintext P:\t" + convertToString(stateP));
            out.println("Running time:\t" + (endTime-startTime) + " ms");
            out.close();
            
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Rijndael.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /* OPERATIONS */
    
    /**
     * Regular version of SubstituteBytes operation.
     * Substitute bytes using S-box
     * @param state input state
     * @return modified state
     */
    private byte[] substituteBytes(byte[] state) {
        byte[] result = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            // For each entry in state, apply the S-box.
            // Add 0xff to ensure no negative vals.
            result[i] = (byte)(S[state[i] & 0xff]);
        }
        return result;
    }
    
    /**
     * Inverse version of SubstituteBytes operation.
     * Substitute bytes using inverse S-box
     * @param state input state
     * @return modified state
     */
    private byte[] invSubstituteBytes(byte[] state) {
        byte[] result = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            // For each entry in state, apply the inverse S-box.
            // Add 0xff to ensure no negative vals.
            result[i] = (byte)(INV_S[state[i] & 0xff]);
        }
        return result;
    }
    
    /**
     * Regular version of ShiftRows operation.
     * Shift rows to left according to AES specification.
     * @param state input state
     * @return modified state
     */
    private byte[] shiftRows(byte[] state) {
        byte[] result = new byte[state.length];
        for (int i = 0; i < result.length; i++) {
            // For each entry in state, apply the shift operation.
            result[i] = state[SHIFT[i]];
        }
        return result;
    }
    
    /**
     * Inverse version of ShiftRows operation.
     * Shift rows to right according to AES specification.
     * @param state input state
     * @return modified state
     */
    private byte[] invShiftRows(byte[] state) {
        byte[] result = new byte[state.length];
        for (int i = 0; i < result.length; i++) {
            // For each entry in state, apply the shift operation.
            result[i] = state[INV_SHIFT[i]];
        }
        return result;
    }
    
    /**
     * The regular MixColumns operation.
     * Mix columns according to AES specification using multiplication in
     * GaloisField(2^8).
     * @param state input state
     * @return modified state
     */
    private byte[] mixColumns(byte[] state) {
        // Create Galois field for calculations
        GaloisField gf = new GaloisField(FIELD_SIZE, IRREDUCIBLE_POLYNOMIAL);
        byte[] result = new byte[state.length]; // Result will be stored here
        for (int i = 0; i < state.length; i++) {
            int row = i%4; // 0,1,2,3,0,1,2,3,…
            int col = (i/4)*4; // 0,0,0,0,4,4,4,4,8,8,8,8,…
            // Matrix multiplication: Resulting elements are XORed sums
            // Constants used in sum from http://en.wikipedia.org/wiki/Rijndael_mix_columns
            // Add 0xff to ensure no negative vals.
            switch (row) {
                case 0: 
                    result[i] = (byte) (gf.multiply(state[col+0] & 0xff, 2) ^
                                        gf.multiply(state[col+1] & 0xff, 3) ^
                                        gf.multiply(state[col+2] & 0xff, 1) ^
                                        gf.multiply(state[col+3] & 0xff, 1));
                    break;
                case 1: 
                    result[i] = (byte) (gf.multiply(state[col+0] & 0xff, 1) ^
                                        gf.multiply(state[col+1] & 0xff, 2) ^
                                        gf.multiply(state[col+2] & 0xff, 3) ^
                                        gf.multiply(state[col+3] & 0xff, 1));
                    break;
                case 2: 
                    result[i] = (byte) (gf.multiply(state[col+0] & 0xff, 1) ^
                                        gf.multiply(state[col+1] & 0xff, 1) ^
                                        gf.multiply(state[col+2] & 0xff, 2) ^
                                        gf.multiply(state[col+3] & 0xff, 3));
                    break;
                case 3: 
                    result[i] = (byte) (gf.multiply(state[col+0] & 0xff, 3) ^
                                        gf.multiply(state[col+1] & 0xff, 1) ^
                                        gf.multiply(state[col+2] & 0xff, 1) ^
                                        gf.multiply(state[col+3] & 0xff, 2));
                    break;    
            }
        }
        return result;
    }
    
    /**
     * The inverse MixColumns operation.
     * Mix columns according to AES specification using multiplication in
     * GaloisField(2^8).
     * @param state input state
     * @return modified state
     */
    private byte[] invMixColumns(byte[] state) {
        // Create Galois field for calculations
        GaloisField gf = new GaloisField(FIELD_SIZE, IRREDUCIBLE_POLYNOMIAL);
        byte[] result = new byte[state.length]; // Result will be stored here
        for (int i = 0; i < state.length; i++) {
            int row = i%4; // 0,1,2,3,0,1,2,3,…
            int col = (i/4)*4; // 0,0,0,0,4,4,4,4,8,8,8,8,…
            // Matrix multiplication: Resulting elements are XORed sums
            // Constants used in sum from http://en.wikipedia.org/wiki/Rijndael_mix_columns
            // Add 0xff to ensure no negative vals.
            switch (row) {
                case 0: 
                    result[i] = (byte) (gf.multiply(state[col+0] & 0xff, 14) ^
                                        gf.multiply(state[col+1] & 0xff, 11) ^
                                        gf.multiply(state[col+2] & 0xff, 13) ^
                                        gf.multiply(state[col+3] & 0xff, 9));
                    break;
                case 1:
                    result[i] = (byte) (gf.multiply(state[col+0] & 0xff, 9) ^
                                        gf.multiply(state[col+1] & 0xff, 14) ^
                                        gf.multiply(state[col+2] & 0xff, 11) ^
                                        gf.multiply(state[col+3] & 0xff, 13));
                    break;
                case 2:
                    result[i] = (byte) (gf.multiply(state[col+0] & 0xff, 13) ^
                                        gf.multiply(state[col+1] & 0xff, 9) ^
                                        gf.multiply(state[col+2] & 0xff, 14) ^
                                        gf.multiply(state[col+3] & 0xff, 11));
                    break;
                case 3:
                    result[i] = (byte) (gf.multiply(state[col+0] & 0xff, 11) ^
                                        gf.multiply(state[col+1] & 0xff, 13) ^
                                        gf.multiply(state[col+2] & 0xff, 9) ^
                                        gf.multiply(state[col+3] & 0xff, 14));
                    break;    
            }
        }
        return result;
    }
    
    /**
     * The regular AddRoundKey operation.
     * Its inverse is the same.
     * @param state input state
     * @param key en/decryption key
     * @return modified state
     */
    private byte[] addRoundKey(byte[] state, byte[] key) {
        // State XORed with key.
        return xor(state, key);
    }
    
    /* KEY EXPANSION */
    
    /**
     * Main part of key schedule.
     * Adapted from Specification for the Advanced Encryption Standard (AES)
     * Function g applied to every 4th word: Rotate, S-box, Rcon
     * @param key initial cipher key
     * @return expanded set of keys
     */
    private byte[][] expand(byte[] key) {
        // For this algorithm, store 44 words in two-dimensional array
        byte[][] result = new byte[44][4];
        // First 4 Words are simply the cipher key
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[i][j] = key[4*i+j];
            }
        }
        // Remaining keys are derived from previous ones
        for (int i = 4; i < 44; i++) {
            byte[] temp = result[i-1]; // Recall last word
            if (i % 4 == 0) { // Apply g for each 4th word
                temp = substituteBytes(rotate(temp));
                temp[0] = (byte)(RCON[i/4] ^ temp[0]);
            }
            // New word is last word XORed with 4th last word
            result[i] = xor(result[i-4], temp);
        }
                
        return result;
    }
    
    /**
     * The Rotate function.
     * Shifts the words by one and rotates the last one
     * @param word array of words
     * @return rotated array of words
     */
    private byte[] rotate(byte[] word) {
        byte[] result = new byte[word.length];
        for (int i = 0; i < word.length-1; i++) {
            result[i] = word[i+1]; // Shift by one
        }
        result[word.length-1] = word[0]; // Wrap around
        return result;
    }
    
    /* HELPER METHODS */
    
    /**
     * XOR two byte vectors.
     * @param a byte vector
     * @param b byte vector
     * @return result
     */
    private byte[] xor(byte[] a, byte[] b) {
        assert(a.length==b.length);
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte)(a[i] ^ b[i]); // XOR each element
        }
        return result;
    }
    
    /**
     * Map a sequence of expanded keys.
     * Since I am working with [11][16] key structure in the main algorithm,
     * i use this function to convert the [44][4] generated from key expansion.
     * @param key key in [44][4] format
     * @return key in [11][16] format
     */
    private byte[][] mapKey(byte[][] key) {
        byte[][] result = new byte[11][16];
        int dim1 = 0, dim2 = 0;
        for (int i = 0; i < result.length; i++) {
            for (int j = 0; j < result[0].length; j++) {
                result[i][j] = key[dim1][dim2]; // Copy to [11][16] structure
                if (dim2 == key[dim1].length-1) { // Reached threshold
                    dim1++; // Increment dimension 1
                    dim2=0; // Reset dimension 2
                }
                else dim2++; // Increment dimension 2
            }
        }
        
        return result;
    }
    
    /**
     * Print a state.
     * For debugging
     * @param state state
     */
    private void printState(byte[] state) {
        String result = "State: ";
        for (byte b: state) {
            //result = result + "" + (b & 0xff) + " ";
            result = result + "" + Integer.toHexString(b & 0xff) + " ";
        }
        System.out.println(result);
    }
    
    /**
     * Print GaloisField multiplication table.
     * For debugging
     * @param fieldSize field size
     * @param irrPol irreducible polynomial
     * @param mult number to multiply with
     * @param length length of the table
     */
    private void printMultTable(int fieldSize, int irrPol, int mult, int length) {
        GaloisField gf = new GaloisField(fieldSize, irrPol);
        System.out.println("GaloisField table with size: " + fieldSize + " and irrPol: " + irrPol + " for multiplication with: " + mult);
        for (int i = 0; i < length; i++) {
            System.out.print(Integer.toHexString(gf.multiply(mult, i) & 0xff) + ", ");
        }
        System.out.println();
    }
    
    /**
     * Alter state in one bit position.
     * @param state input state
     * @param pos position to alter
     * @return altered state
     */
    private byte[] alteredState(byte[] state, int pos) {
        state[pos/8] ^= (byte)Math.pow(2, 7-pos%8);
        return state;
    }
    
    /**
     * Calculate hamming distance between two states.
     * @param a state
     * @param b state
     * @return hamming distance
     */
    private int hammingDist(byte[] a, byte[] b) {
        int result = 0;
        for (int i = 0; i < a.length; i++) { // go through indiv bytes
            byte x = a[i];
            byte y = b[i];
            for (int j = 0; j < 8; j++) {
                if ((x&1)!=(y&1)) { // check for each bit position if not same
                    result++;
                }
                x >>= 1; // Shift
                y >>= 1; // Shift
            }
        }
        return result;
    }
    
    /**
     * Compute the arithmetic mean of an array.
     * Assumed from task description that values are to be rounded to integers.
     * @param values array
     * @return average
     */
    private int average(int[] values) {
        int result = 0;
        for (int i: values) result += i;
        return (int)Math.round((result*1.0d)/values.length);
    }
    
    /**
     * Convert a String of 0 and 1 to byte[] state.
     * @param input String of 0 and 1
     * @return byte[] state
     */
    private byte[] convertFromString(String input) {
        assert(input.length()==128);
        byte[] result = new byte[16];
        for (int i = 0; i < 16; i++) {
            // Use Integer.parseInt with base 2
            result[i] = (byte)Integer.parseInt(input.substring(8*i, 8*i+8), 2);
        }
        return result;
    }
    
    /**
     * Convert a byte[] state to String of 0 and 1.
     * @param input byte[] state
     * @return String of 0 and 1
     */
    private String convertToString(byte[] state) {
        String result = "";
        for (int i = 0; i < state.length; i++) {
            // Use Integer.toBinaryString -> Have to add 0xff to avoid negative
            // Additionally make sure that empty space is filled with 0's
            result = result + String.format("%8s", Integer.toBinaryString(state[i] & 0xff)).replace(" ", "0");
        }
        return result;
    }
}