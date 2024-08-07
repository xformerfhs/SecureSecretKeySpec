/*
 * SPDX-FileCopyrightText: 2021-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023-2024 Frank Schwab
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Frank Schwab
 *
 * Changes:
 *     2021-05-28: V1.0.0: Created. fhs
 *     2021-09-01: V1.0.1: Some small refactoring. fhs
 *     2022-11-07: V1.1.0: Better mixing of bytes from and to buffers. fhs
 *     2022-11-08: V1.2.0: Name all constants. fhs
 *     2022-12-22: V1.2.1: Removed unnecessary constant. fhs
 *     2023-05-20: V1.2.2: Renamed instance variables. fhs
 */
 
package de.xformerfhs.securesecretkeyspec.crypto;

import de.xformerfhs.securesecretkeyspec.arrays.ArrayHelper;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Class to get masks for array indices
 *
 * @author Frank Schwab
 * @version 1.2.2
 */
public class MaskedIndex {
   // ======== Private constants ========

   /**
    * Key size.
    */
   static final int KEY_SIZE = 16;  // I.e. 128 bits

   /**
    * Buffer size.
    */
   static final int BUFFER_SIZE = 16;

   /**
    * Mask for additions modulo buffer size.
    */
   static final int BUFFER_SIZE_MASK = BUFFER_SIZE - 1;

   /**
    * Modulo value for the offset of an integer in a buffer.
    */
   static final int MOD_BUFFER_SIZE_FOR_INTEGER = BUFFER_SIZE - 3;

   /**
    * Byte value to prime buffer with.
    */
   static final byte BUFFER_PRIMER = (byte) 0x5a;

   /**
    * Step size for setting and getting bytes in the buffer.
    */
   static final int STEP_SIZE = 3;

   /**
    * Number of bits to shift for a byte shift.
    */
   static final int BYTE_SHIFT = 8;

   /**
    * Byte mask for integers.
    */
   static final int INT_BYTE_MASK = 0xff;


   // ======== Instance variables ========

   /**
    * Encryptor to use.
    */
   private Cipher encryptor;

   /**
    * Source buffer for mask generation.
    */
   private final byte[] sourceBuffer = new byte[BUFFER_SIZE];

   /**
    * Buffer for encryption result.
    */
   private final byte[] maskBuffer = new byte[BUFFER_SIZE];


   // ======== Constructor ========

   /**
    * The constructor for an instance of MaskedIndex.
    */
   public MaskedIndex() {
      initializeCipher();
   }


   // ======== Public methods ========

   /**
    * Get an integer mask for an index.
    *
    * @param forIndex The index to use.
    * @return The int mask for the given index.
    */
   public synchronized int getIntMask(final int forIndex) {
      final int sanitizedIndex = forIndex & Integer.MAX_VALUE;

      getMaskBuffer(sanitizedIndex);

      final int result = getMaskIntFromArray(this.maskBuffer,
            (7 * (sanitizedIndex % MOD_BUFFER_SIZE_FOR_INTEGER) + 3) % MOD_BUFFER_SIZE_FOR_INTEGER);

      ArrayHelper.clear(this.maskBuffer);

      return result;
   }

   /**
    * Get a byte mask for an index.
    *
    * @param forIndex The index to use.
    * @return The byte mask for the given index.
    */
   public synchronized byte getByteMask(final int forIndex) {
      final int sanitizedIndex = forIndex & Integer.MAX_VALUE;

      getMaskBuffer(sanitizedIndex);

      final byte result = this.maskBuffer[(13 * (sanitizedIndex & BUFFER_SIZE_MASK) + 5) & BUFFER_SIZE_MASK];

      ArrayHelper.clear(this.maskBuffer);

      return result;
   }


   // ======== Private methods ========

   /**
    * Calculate a buffer full of mask bytes.
    *
    * @param sanitizedIndex Sanitized index to use for the mask calculation.
    */
   private void getMaskBuffer(final int sanitizedIndex) {
      Arrays.fill(this.sourceBuffer, BUFFER_PRIMER);

      final int offset = (11 * (sanitizedIndex % MOD_BUFFER_SIZE_FOR_INTEGER) + 2) % MOD_BUFFER_SIZE_FOR_INTEGER;
      storeIntInArray(sanitizedIndex, this.sourceBuffer, offset);

      try {
         this.encryptor.doFinal(this.sourceBuffer, 0, this.sourceBuffer.length, this.maskBuffer, 0);
      } catch (Exception ex) {
         // BadPaddingException, IllegalBlockSizeException and ShortBufferException can never happen
      } finally {
         ArrayHelper.clear(this.sourceBuffer);
      }
   }

   /**
    * Initialize the cipher.
    */
   private void initializeCipher() {
      final byte[] key = new byte[KEY_SIZE];

      final SecureRandom sprng = SecureRandomFactory.getSensibleSingleton();

      sprng.nextBytes(key);

      try {
         // ECB is an insecure mode. That is *no* problem as
         // the cipher is only used for generating an obfuscation mask.
         this.encryptor = Cipher.getInstance("AES/ECB/NoPadding");

         // This has to be "SecretKeySpec" and not "SecureSecretKeySpec".
         // Otherwise, we would have an infinite loop here.
         SecretKeySpec maskKey = new SecretKeySpec(key, "AES");

         this.encryptor.init(Cipher.ENCRYPT_MODE, maskKey);
      } catch (Exception ex) {
         // InvalidKeyException, NoSuchAlgorithmException and NoSuchPaddingException can never happen
      } finally {
         ArrayHelper.clear(key);
      }
   }

   /**
    * Stores the bytes of an integer in an existing array.
    *
    * @param sourceInt Integer to convert.
    * @param destArray Destination byte array.
    * @param startPos  Start position in the byte array.
    */
   private void storeIntInArray(final int sourceInt, final byte[] destArray, final int startPos) {
      int toPos = startPos;
      int work = sourceInt;

      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos = (toPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos = (toPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos = (toPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);
   }

   /**
    * Get a mask integer from the bytes in an array.
    *
    * @param sourceArray Byte array to get the integer from.
    * @param startPos    Start position in the byte array.
    * @return Mask integer.
    */
   private int getMaskIntFromArray(final byte[] sourceArray, final int startPos) {
      int result;
      int fromPos = startPos;

      result = (sourceArray[fromPos] & INT_BYTE_MASK);  // This stupid Java sign extension!!!!

      result <<= BYTE_SHIFT;
      fromPos = (fromPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      result <<= BYTE_SHIFT;
      fromPos = (fromPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      result <<= BYTE_SHIFT;
      fromPos = (fromPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      return result;
   }
}
