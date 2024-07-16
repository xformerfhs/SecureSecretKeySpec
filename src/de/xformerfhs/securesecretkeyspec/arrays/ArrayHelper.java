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
 *     2021-08-30: V1.0.0: Created. fhs
 *     2021-09-01: V1.0.1: Added clear methods for integer arrays. fhs
 *     2022-06-22: V1.0.3: Corrected data type of CLEAR_INT. fhs
 *     2023-05-11: V1.1.0: Added constantTimeIsEqual method. fhs
 *     2023-05-16: V1.1.1: Use min function. fhs
 *     2024-07-13: V1.2.0: Add concat, copyOrEmpty and splitTail. fhs
 *     2024-07-14: V1.2.1: Clean up methods. fhs
 */

package de.xformerfhs.securesecretkeyspec.arrays;

import java.util.Arrays;
import java.util.Objects;

/**
 * Helper class for array operations.
 *
 * @author Frank Schwab
 * @version 1.2.1
 */
public class ArrayHelper {
   // ======== Private constants ========

   // Fill values for clear methods

   private static final byte CLEAR_BYTE = (byte) 0;
   private static final char CLEAR_CHAR = '\0';
   private static final int CLEAR_INT = 0;

   /**
    * Constant empty byte array to return with some functions.
    */
   private static final byte[] EMPTY_BYTE_ARRAY = {};


   // ======== Constructor ========

   /**
    * Private constructor.
    *
    * <p>This class is not meant to be instanced.</p>
    */
   private ArrayHelper() {
      throw new IllegalStateException("This class is not meant to be instanced");
   }


   // ======== Public methods ========

   // It would have been easier to declare a generic "clear" method for all Number type arrays.
   // However, Java's generics are designed very badly, as they do not work with primitive data types
   // and it is impossible to use "new" with a generic data type.
   // So generics can not be used and each data type has its own method.

   /**
    * Clear a byte array.
    *
    * @param a Byte array to clear.
    */
   public static void clear(final byte[] a) {
      Arrays.fill(a, CLEAR_BYTE);
   }

   /**
    * Clear a character array.
    *
    * @param a Character array to clear.
    */
   public static void clear(final char[] a) {
      Arrays.fill(a, CLEAR_CHAR);
   }

   /**
    * Clear an integer array.
    *
    * @param a Integer array to clear.
    */
   public static void clear(final int[] a) {
      Arrays.fill(a, CLEAR_INT);
   }

   /**
    * Clear a byte array and do not throw an exception if it is null.
    *
    * @param a Byte array to clear.
    */
   public static void safeClear(final byte[] a) {
      if (a != null)
         Arrays.fill(a, CLEAR_BYTE);
   }

   /**
    * Clear a character array and do not throw an exception if it is null.
    *
    * @param a Character array to clear.
    */
   public static void safeClear(final char[] a) {
      if (a != null)
         Arrays.fill(a, CLEAR_CHAR);
   }

   /**
    * Clear an integer array and do not throw an exception if it is null.
    *
    * @param a Integer array to clear.
    */
   public static void safeClear(final int[] a) {
      if (a != null)
         Arrays.fill(a, CLEAR_INT);
   }

   /**
    * Concatenate byte arrays.
    *
    * @param sources Byte arrays to concatenate.
    * @return Concatenation of the source byte arrays.
    */
   public static byte[] concat(final byte[]... sources) {
      // 1. Calculate total length of result.
      int totalLength = 0;
      for (byte[] s : sources)
         totalLength += s.length;

      // 2. Allocate result array.
      final byte[] result = new byte[totalLength];

      // 3. Copy sources to result.
      int offset = 0;
      for (byte[] s : sources) {
         final int sLength = s.length;
         System.arraycopy(s, 0, result, offset, sLength);
         offset += sLength;
      }

      return result;
   }

   /**
    * Split a tail from a byte array.
    *
    * @param source     Source byte array.
    * @param tailLength length of tail to split.
    * @return Array of two byte arrays (head, tail).
    * @throws IllegalArgumentException if {@code tailLength} has an invalid length.
    */
   public static byte[][] splitTail(final byte[] source, final int tailLength) {
      final int sourceLength = source.length;
      if (tailLength > 0 && tailLength < sourceLength) {
         final int headLength = sourceLength - tailLength;
         final byte[] head = Arrays.copyOf(source, headLength);
         final byte[] tail = Arrays.copyOfRange(source, headLength, sourceLength);

         return new byte[][]{head, tail};
      } else
         throw new IllegalArgumentException("Invalid tail length: " + tailLength);
   }

   /**
    * Get a copy of the source or an empty byte array, if the source is {@code null}.
    *
    * @param source Source byte array.
    * @return Copy of the source array or an empty byte array, if {@code source} is {@code null}.
    */
   public static byte[] copyOrEmpty(final byte[] source) {
      if (source != null)
         return Arrays.copyOf(source, source.length);
      else
         return EMPTY_BYTE_ARRAY;
   }

   /**
    * Get a copy of a byte array, or throw an exception, if it is {@code null}.
    *
    * @param source    Source byte array.
    * @return Copy of {@code source}.
    * @throws NullPointerException if {@code source} is null.
    */
   public static byte[] copyOrException(final byte[] source) {
      return Arrays.copyOf(Objects.requireNonNull(source), source.length);
   }

   /**
    * Compares two byte arrays in constant time.
    *
    * <p>
    * The execution time depends only on the length of the shortest array.
    * This makes side-channel attacks that measure the execution time of a
    * comparison impossible.
    * </p>
    *
    * @param a First array.
    * @param b Second array.
    * @return {@code true}, if the arrays have the same length and the elements have the same values, {@code false}, if not.
    * @throws NullPointerException if {@code a} or {@code b} is null.
    */
   public static boolean constantTimeEquals(final byte[] a, final byte[] b) {
      final int aLength = Objects.requireNonNull(a).length;
      final int bLength = Objects.requireNonNull(b).length;

      int result = aLength ^ bLength; // Get difference in the lengths

      final int compareLength = Math.min(aLength, bLength);

      // Now collect the differences for each element
      for (int i = 0; i < compareLength; i++) {
         result |= a[i] ^ b[i];
      }

      return result == 0;  // This is only true if the arrays have the same lengths and the same element values.
   }
}
