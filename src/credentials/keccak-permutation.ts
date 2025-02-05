/**
 * this contains just the Keccac permutation function
 *
 * TODO: export this from o1js
 *
 * the code in this file was copied and modified from o1js
 * https://github.com/o1-labs/o1js
 */
import { Field, Gadgets, Provable } from 'o1js';
import { assert } from '../util.ts';

export { Keccak, KeccakState };

// Keccak permutation function with a constant number of rounds
function permutation(state: Field[][]): Field[][] {
  return ROUND_CONSTANTS.reduce((state, rc) => round(state, rc), state);
}

// One round of the Keccak permutation function.
// iota o chi o pi o rho o theta
function round(state: Field[][], rc: bigint): Field[][] {
  const stateA = state;
  const stateE = theta(stateA);
  const stateB = piRho(stateE);
  const stateF = chi(stateB);
  const stateD = iota(stateF, rc);
  return stateD;
}

// First algorithm in the compression step of Keccak for 64-bit words.
// C[i] = A[i,0] xor A[i,1] xor A[i,2] xor A[i,3] xor A[i,4]
// D[i] = C[i-1] xor ROT(C[i+1], 1)
// E[i,j] = A[i,j] xor D[i]
// In the Keccak reference, it corresponds to the `theta` algorithm.
// We use the first index of the state array as the i coordinate and the second index as the j coordinate.
const theta = (state: Field[][]): Field[][] => {
  const stateA = state;

  // XOR the elements of each row together
  // for all i in {0..4}: C[i] = A[i,0] xor A[i,1] xor A[i,2] xor A[i,3] xor A[i,4]
  const stateC = stateA.map((row) => row.reduce(xor));

  // for all i in {0..4}: D[i] = C[i-1] xor ROT(C[i+1], 1)
  const stateD = Array.from({ length: 5 }, (_, i) =>
    xor(
      stateC[(i + 5 - 1) % 5]!,
      Gadgets.rotate64(stateC[(i + 1) % 5]!, 1, 'left')
    )
  );

  // for all i in {0..4} and j in {0..4}: E[i,j] = A[i,j] xor D[i]
  const stateE = stateA.map((row, index) =>
    row.map((elem) => xor(elem, stateD[index]!))
  );

  return stateE;
};

// Second and third steps in the compression step of Keccak for 64-bit words.
// pi: A[i,j] = ROT(E[i,j], r[i,j])
// rho: A[i,j] = A'[j, 2i+3j mod 5]
// piRho: B[j,2i+3j] = ROT(E[i,j], r[i,j])
// which is equivalent to the `rho` algorithm followed by the `pi` algorithm in the Keccak reference as follows:
// rho:
// A[0,0] = a[0,0]
// | i |  =  | 1 |
// | j |  =  | 0 |
// for t = 0 to 23 do
//   A[i,j] = ROT(a[i,j], (t+1)(t+2)/2 mod 64)))
//   | i |  =  | 0  1 |   | i |
//   |   |  =  |      | * |   |
//   | j |  =  | 2  3 |   | j |
// end for
// pi:
// for i = 0 to 4 do
//   for j = 0 to 4 do
//     | I |  =  | 0  1 |   | i |
//     |   |  =  |      | * |   |
//     | J |  =  | 2  3 |   | j |
//     A[I,J] = a[i,j]
//   end for
// end for
// We use the first index of the state array as the i coordinate and the second index as the j coordinate.
function piRho(state: Field[][]): Field[][] {
  const stateE = state;
  const stateB = KeccakState.zeros();

  // for all i in {0..4} and j in {0..4}: B[j,2i+3j] = ROT(E[i,j], r[i,j])
  for (let i = 0; i < 5; i++) {
    for (let j = 0; j < 5; j++) {
      stateB[j]![(2 * i + 3 * j) % 5] = Gadgets.rotate64(
        stateE[i]![j]!,
        ROT_TABLE[i]![j]!,
        'left'
      );
    }
  }

  return stateB;
}

// Fourth step of the compression function of Keccak for 64-bit words.
// F[i,j] = B[i,j] xor ((not B[i+1,j]) and B[i+2,j])
// It corresponds to the chi algorithm in the Keccak reference.
// for j = 0 to 4 do
//   for i = 0 to 4 do
//     A[i,j] = a[i,j] xor ((not a[i+1,j]) and a[i+2,j])
//   end for
// end for
function chi(state: Field[][]): Field[][] {
  const stateB = state;
  const stateF = KeccakState.zeros();

  // for all i in {0..4} and j in {0..4}: F[i,j] = B[i,j] xor ((not B[i+1,j]) and B[i+2,j])
  for (let i = 0; i < 5; i++) {
    for (let j = 0; j < 5; j++) {
      stateF[i]![j]! = xor(
        stateB[i]![j]!,
        Gadgets.and(
          // We can use unchecked NOT because the length of the input is constrained to be 64 bits thanks to the fact that it is the output of a previous Xor64
          Gadgets.not(stateB[(i + 1) % 5]![j]!, 64, false),
          stateB[(i + 2) % 5]![j]!,
          64
        )
      );
    }
  }

  return stateF;
}

// Fifth step of the permutation function of Keccak for 64-bit words.
// It takes the word located at the position (0,0) of the state and XORs it with the round constant.
function iota(state: Field[][], rc: bigint): Field[][] {
  const stateG = state;

  stateG[0]![0] = xor(stateG[0]![0]!, Field.from(rc));

  return stateG;
}

// FUNCTIONS ON KECCAK STATE

/**
 * The internal state of the Keccak hash function is\
 * a 5x5 matrix of 64-bit words.
 */
type KeccakState = Field[][];
const KeccakState = {
  /**
   * Create a state of all zeros
   */
  zeros(): KeccakState {
    return Array.from(Array(5), (_) => Array(5).fill(Field.from(0)));
  },

  /**
   * Flatten state to words
   */
  toWords(state: KeccakState): Field[] {
    const words = Array<Field>(25);
    for (let j = 0; j < 5; j++) {
      for (let i = 0; i < 5; i++) {
        words[5 * j + i] = state[i]![j]!;
      }
    }
    return words;
  },

  /**
   * Compose words to state
   */
  fromWords(words: Field[]): KeccakState {
    const state = KeccakState.zeros();
    for (let j = 0; j < 5; j++) {
      for (let i = 0; i < 5; i++) {
        state[i]![j] = words[5 * j + i]!;
      }
    }
    return state;
  },

  /**
   * XOR two states together and return the result
   */
  xor(a: KeccakState, b: KeccakState): KeccakState {
    assert(
      a.length === 5 && a[0]!.length === 5,
      `invalid \`a\` dimensions (should be ${5})`
    );
    assert(
      b.length === 5 && b[0]!.length === 5,
      `invalid \`b\` dimensions (should be ${5})`
    );

    // Calls xor() on each pair (i,j) of the states input1 and input2 and outputs the output Fields as a new matrix
    return a.map((row, i) => row.map((x, j) => xor(x, b[i]![j]!)));
  },

  provable: Provable.Array(Provable.Array(Field, 5), 5),
};

// KECCAK CONSTANTS

// Creates the 5x5 table of rotation offset for Keccak modulo 64
//  | i \ j |  0 |  1 |  2 |  3 |  4 |
//  | ----- | -- | -- | -- | -- | -- |
//  | 0     |  0 | 36 |  3 | 41 | 18 |
//  | 1     |  1 | 44 | 10 | 45 |  2 |
//  | 2     | 62 |  6 | 43 | 15 | 61 |
//  | 3     | 28 | 55 | 25 | 21 | 56 |
//  | 4     | 27 | 20 | 39 |  8 | 14 |
const ROT_TABLE = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

// Round constants for Keccak
// From https://keccak.team/files/Keccak-reference-3.0.pdf
const ROUND_CONSTANTS = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];

// UTILITY FUNCTIONS

// xor which avoids doing anything on 0 inputs
// (but doesn't range-check the other input in that case)
function xor(x: Field, y: Field): Field {
  if (x.isConstant() && x.toBigInt() === 0n) return y;
  if (y.isConstant() && y.toBigInt() === 0n) return x;
  return Gadgets.xor(x, y, 64);
}

// EXPORT

const Keccak = {
  permutation,
  State: KeccakState,
};
