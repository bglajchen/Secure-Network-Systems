public class Crypto
{
	public static int[] DES (int[] plaintext, int[] key)
	{
		int[] leftBlock = new int[32];
                int[] rightBlock = new int[32];
		int[] first_key_permutation = {
			57, 49, 41, 33, 25, 17, 9,
			1, 58, 50, 42, 34, 26, 18,
			10, 2, 59, 51, 43, 35, 27,
			19, 11, 3, 60, 52, 44, 36,
			63, 55, 47, 39, 31, 23, 15,
			7, 62, 54, 46, 38, 30, 22,
			14, 6, 61, 53, 45, 37, 29,
			21, 13, 5, 28, 20, 12, 4
		};
		int[] second_key_permutation = {
			14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32
		};
		int[] permuted_key = new int[56];
		int[] round_keys = new int[896];
		int[] permuted_round_keys = new int[768];
		int[] shift_code = {
			1, 2, 2, 2, 2,
			2, 2, 1, 2, 2,
			2, 2, 2, 2, 1
		};
		int[] first_string_permutation = {
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17, 9, 1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7,
		};
		int[] input = new int[64];
		int[] prime_rightBlock = new int[32];
		int[] final_rightBlock = new int[32];
		int[] third_string_permutation = {
			40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25
		};
		int[] output = new int[64];
		int[] value = new int[64];

		// permute the key
		for (int i = 0; i < permuted_key.length; i++)
		{
			permuted_key[i] = key[first_key_permutation[i] - 1];
		}

		// split the permuted key, left shift each half, then concatenate
		// generates first row of round_keys only
		int v = permuted_key.length;
		round_keys[(v/2) - 1] = permuted_key[0];
		round_keys[v - 1] = permuted_key[v / 2];
		for (int i = 0; i < (v/2) - 1; i++)
		{
			round_keys[i] = permuted_key[i + 1];
			round_keys[i + (v/2)] = permuted_key[i + (v/2) + 1];
		}

		// generate the rest of the rows for round_keys
		for (int i = 56; i < round_keys.length; i = i + 56)
		{
			if (shift_code[i / 56 - 1] == 1)
			{
				round_keys[i + (v/2) - 1] = round_keys[i - 56];
				round_keys[i + v - 1] = round_keys[(i - 56) + (v/2)];
				for (int j = 0; j < ((v/2) - 1); j++)
				{
					round_keys[i + j] = round_keys[(i - 56) + j + 1];
					round_keys[i + j + (v/2)] = round_keys[(i - 56) + j + (v/2) + 1];
				}
			} else {
				round_keys[i + (v/2) - 2] = round_keys[i - 56];
				round_keys[i + (v/2) - 1] = round_keys[i - 56 + 1];
				round_keys[i + v - 2] = round_keys[(i - 56) + (v/2)];
				round_keys[i + v - 1] = round_keys[(i - 56) + (v/2) + 1];
				for (int j = 0; j < ((v/2) - 2); j++)
				{
					round_keys[i + j] = round_keys[(i -56) + j + 2];
					round_keys[i + j + (v/2)] = round_keys[(i - 56) + j + (v/2) + 2];
				}
			}
		}

		// permute the keys again
		for (int i = 0; i < (permuted_round_keys.length / 48); i++)
		{
			for (int j = 0; j < second_key_permutation.length; j++)
			{
				permuted_round_keys[(i * 48) + j] = round_keys[(i * 56) + (second_key_permutation[j] - 1)];
			}
		}

		// permute plaintext
		for (int i = 0; i < input.length; i++)
		{
			input[i] = plaintext[first_string_permutation[i] - 1];
		}

		// 16 rounds of key encryption
		for (int round = 0; round < 16; round++)
		{
			for (int i = 0; i < leftBlock.length; i++)
			{
				leftBlock[i] = input[i];
				rightBlock[i] = input[i + leftBlock.length];
			}

			prime_rightBlock = mangler_function(rightBlock, permuted_round_keys, round);

			for (int i = 0; i < prime_rightBlock.length; i++)
			{
				input[i] = rightBlock[i];
				input[i+32] = ((prime_rightBlock[i] + leftBlock[i]) % 2);
			}

		}

		// switch the left and right sides
		for (int i = 0; i < (input.length/2); i++)
		{
			output[i] = input[i+32];
			output[i+32] = input[i];
		}

		// final permutation
		for (int i = 0; i < output.length; i++)
		{
			value[i] = output[third_string_permutation[i] - 1];
		}

		return value;
	}

	public static int[] mangler_function(int[] input, int[] keys, int round)
	{
		int[] mangle_permutation = {
			32, 1, 2, 3, 4, 5,
			4, 5, 6, 7, 8, 9,
			8, 9, 10, 11, 12, 13,
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25,
			24, 25, 26, 27, 28, 29,
			28, 29, 30, 31, 32, 1
		};
		int[/*depth*/][/*rows*/][/*column*/] s =
                {
                        {
                                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
                        },
                        {
                                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
                        },
			{
				{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
			},
			{
                                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
			},
			{
                                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
			},
			{
                                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
			},
			{
                                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
			},
			{
                                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
			}
                };
		int[] second_string_permutation = {
			16, 7, 20, 21,
			29, 12, 28, 17,
			1, 15, 23, 26,
			5, 18, 31, 10,
			2, 8, 24, 14,
			32, 27, 3, 9,
			19, 13, 30, 6,
			22, 11, 4, 25
		};
		int[] mangle = new int[48];
		int[] output = new int[32];
		int[][] conversion = new int[8][6];
		int[] value = new int[32];
		for (int i = 0; i < mangle.length; i++)
		{
			mangle[i] = input[mangle_permutation[i] - 1];
			mangle[i] = ((mangle[i] + keys[(round * 48) + i]) % 2);
		}

		// split mangle up into 8 sets of 6-bits
		for (int i = 0; i < (mangle.length / 6); i++)
		{
			for (int j = 0; j < (mangle.length / 8); j++)
			{
				conversion[i][j] = mangle[(i*6) + j];
			}
		}

		// convert 6-bits into 4-bits
		StringBuilder to_output = new StringBuilder();
		for (int i = 0; i < 8; i++)
		{
			String tmp = String.valueOf(conversion[i][0]) + String.valueOf(conversion[i][5]);
			int row = Integer.parseInt(tmp, 2);
			tmp = String.valueOf(conversion[i][1]) +
				String.valueOf(conversion[i][2]) +
				String.valueOf(conversion[i][3]) +
				String.valueOf(conversion[i][4]);
			int col = Integer.parseInt(tmp, 2);
			int temp = s[i][row][col];
to_output.append(String.format("%4s", Integer.toBinaryString(temp)).replace(' ','0'));
		}
		String[] tmp = to_output.toString().split("(?!^)");
		for (int i = 0; i < 32; i++)
		{
			output[i] = Integer.parseInt(tmp[i]);
		}

		// permute 32-bit value
		for (int i = 0; i < 32; i++)
		{
			value[i] = output[second_string_permutation[i] - 1];
		}
		output = value;

		return output;
	}

	public static int[] ECB (String plaintext, String key)
	{
		// convert plaintext to StringBuilder of 8-bit binary version
		char[] letters = plaintext.toCharArray();
		int[] num_letters = new int[letters.length];
		StringBuilder string = new StringBuilder();
		for (int i = 0; i < letters.length; i++)
		{
			num_letters[i] = (int) letters[i];
			string.append(String.format("%8s", Integer.toBinaryString(num_letters[i])).replace(' ','0'));
		}

		// turn StringBuilder into 64-bit blocks
		int length = (string.length() / 64);
		String[] var = new String[length + 1];
		StringBuilder temp = new StringBuilder();
		int counter = 0;
		for (int i = 0; i < length; i++)
		{
			var[i] = string.substring(0, 64);
			for (int j = 0; j < 64; j++)
				string.deleteCharAt(0);
			counter++;
		}
		length = string.length();
		for (int i = (int) length; i < 64; i++)
		{
			string.append(0);
		}
		var[counter] = string.substring(0, 64);
		if ((plaintext.length() % 8) != 0){
			counter++;
		}
		int[][] ecb_blocks = new int[counter][64];
		for (int i = 0; i < counter; i++)
		{
			String[] tmp = var[i].split("");
			for (int j = 0; j < 64; j++)
			{
				ecb_blocks[i][j] = Integer.parseInt(tmp[j]);
			}
		}

		// convert key to StringBuilder of 8-bit binary version
                char[] letters_key = key.toCharArray();
                int[] num_letters_key = new int[letters_key.length];
                StringBuilder string_key = new StringBuilder();
                for (int i = 0; i < letters_key.length; i++)
                {
                        num_letters_key[i] = (int) letters_key[i];
			string_key.append(String.format("%8s", Integer.toBinaryString(num_letters_key[i])).replace(' ','0'));
                }
		if (string_key.length() < 64)
			return null;

                // turn StringBuilder into 64-bit blocks
            	String var_key = string_key.substring(0, 64);
		int[] key_block = new int[64];
                String[] tmp = var_key.split("");
                for (int j = 0; j < 64; j++)
                {
                	key_block[j] = Integer.parseInt(tmp[j]);
                }

		// DES return
		int[] return_block = new int[64];
		StringBuilder return_ecb = new StringBuilder();
		for (int i = 0; i < counter; i++)
		{
			return_block = DES(ecb_blocks[i], key_block);
			for (int j = 0; j < return_block.length; j++)
			{
				return_ecb.append(return_block[j]);
			}
		}

		// turn return_ecb back into integers
		length = return_ecb.length() / 8;
		int[] raw_int = new int[(int) length];
		for (int i = 0; i < length; i++)
		{
			String interim = return_ecb.substring(0,8);
			raw_int[i] = Integer.parseInt(interim, 2);
			return_ecb.delete(0,8);
		}

		return raw_int;
	}

	public static int[] CBC (String plaintext, String key, String iv)
	{
		// convert plaintext to StringBuilder of 8-bit binary version
		char[] letters = plaintext.toCharArray();
		int[] num_letters = new int[letters.length];
		StringBuilder string = new StringBuilder();
		for (int i = 0; i < letters.length; i++)
		{
			num_letters[i] = (int) letters[i];
			string.append(String.format("%8s", Integer.toBinaryString(num_letters[i])).replace(' ','0'));
		}

		// turn StringBuilder into 64-bit blocks
		int length = (string.length() / 64);
		String[] var = new String[length + 1];
		StringBuilder temp = new StringBuilder();
		int counter = 0;
		for (int i = 0; i < length; i++)
		{
			var[i] = string.substring(0, 64);
			for (int j = 0; j < 64; j++)
				string.deleteCharAt(0);
			counter++;
		}
		length = string.length();
		for (int i = length; i < 64; i++)
		{
			string.append(0);
		}
		var[counter] = string.substring(0, 64);
		if ((plaintext.length() % 8) != 0){
			counter++;
		}
		int[][] cbc_blocks = new int[counter][64];
		for (int i = 0; i < counter; i++)
		{
			String[] tmp = var[i].split("");
			for (int j = 0; j < 64; j++)
			{
				cbc_blocks[i][j] = Integer.parseInt(tmp[j]);
			}
		}

		// convert key to StringBuilder of 8-bit binary version
                char[] letters_key = key.toCharArray();
                int[] num_letters_key = new int[letters_key.length];
                StringBuilder string_key = new StringBuilder();
                for (int i = 0; i < letters_key.length; i++)
                {
                        num_letters_key[i] = (int) letters_key[i];
			string_key.append(String.format("%8s", Integer.toBinaryString(num_letters_key[i])).replace(' ','0'));
                }
		if (string_key.length() < 64)
			return null;

                // turn StringBuilder into 64-bit block
            	String var_key = string_key.substring(0, 64);
		int[] key_block = new int[64];
                String[] tmp = var_key.split("");
                for (int j = 0; j < 64; j++)
                {
                	key_block[j] = Integer.parseInt(tmp[j]);
                }


		// convert iv to StringBuilder of 8-bit binary version
                char[] letters_iv = iv.toCharArray();
                int[] num_letters_iv = new int[letters_iv.length];
                StringBuilder string_iv = new StringBuilder();
                for (int i = 0; i < letters_iv.length; i++)
                {
                        num_letters_iv[i] = (int) letters_iv[i];
			string_iv.append(String.format("%8s", Integer.toBinaryString(num_letters_iv[i])).replace(' ','0'));
                }
		if (string_iv.length() < 64)
			return null;

                // turn StringBuilder into 64-bit block
            	String var_iv = string_iv.substring(0, 64);
		int[] iv_block = new int[64];
                tmp = var_iv.split("");
                for (int j = 0; j < 64; j++)
                {
                	iv_block[j] = Integer.parseInt(tmp[j]);
                }

		// apply cbc algorithm
		int[] holder = new int[64];		
		int[][] results = new int[counter][64];
		for (int i = 0; i < 64; i++)
		{
			holder[i] = ((cbc_blocks[0][i] + iv_block[i]) % 2);
		}
		results[0] = DES(holder, key_block);
		
		for (int i = 1; i < counter; i++)
		{
			for (int j = 0; j < 64; j++)
			{
				holder[j] = ((cbc_blocks[i][j] + results[0][j]) % 2);
			}
			results[i] = DES(holder, key_block);
		}
		StringBuilder return_cbc = new StringBuilder();
		for (int i = 0; i < counter; i++)
		{
			for (int j = 0; j < 64; j++)
			{
				return_cbc.append(results[i][j]);
			}
		}

		// turn return_ecb back into integers
		length = return_cbc.length() / 8;
		int[] raw_int = new int[(int) length];
		for (int i = 0; i < length; i++)
		{
			String interim = return_cbc.substring(0,8);
			raw_int[i] = Integer.parseInt(interim, 2);
			return_cbc.delete(0,8);
		}

		return raw_int;
	}

}
