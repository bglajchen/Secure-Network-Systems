public class Main extends Crypto
{
	public static void main(String arg[])
	{
		int[] plaintext_des = {
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 1, 0, 0, 0, 1, 1,
			0, 1, 0, 0, 0, 1, 0, 1,
			0, 1, 1, 0, 0, 1, 1, 1,
			1, 0, 0, 0, 1, 0, 0, 1,
			1, 0, 1, 0, 1, 0, 1, 1,
			1, 1, 0, 0, 1, 1, 0, 1,
			1, 1, 1, 0, 1, 1, 1, 1
		};
		int[] key_des = {
			0, 0, 0, 1, 0, 0, 1, 1,
			0, 0, 1, 1, 0, 1, 0, 0,
			0, 1, 0, 1, 0, 1, 1, 1,
			0, 1, 1, 1, 1, 0, 0, 1,
			1, 0, 0, 1, 1, 0, 1, 1,
			1, 0, 1, 1, 1, 1, 0, 0,
			1, 1, 0, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 0, 0, 0, 1
		};
		String plaintext_ecb_cbc_first = "I LOVE SECURITY";
		String plaintext_ecb_cbc_second = "GO GATORS!";
		String plaintext_ecb_cbc_third = "SECURITYSECURITY";
		String key_iv_ecb_cbc = "ABCDEFGH";

		int[] ciphertext_des = DES(plaintext_des, key_des);
		System.out.print("DES Ciphertext: ");
		for (int i = 0; i < ciphertext_des.length; i++)
		{
			System.out.print(ciphertext_des[i]);
		}
		System.out.println("");

		int[] ciphertext_ecb = ECB(plaintext_ecb_cbc_first, key_iv_ecb_cbc);
		System.out.print("ECB Ciphertext: ");
		for (int i = 0; i < ciphertext_ecb.length; i++)
		{
			System.out.print(ciphertext_ecb[i] + " ");
		}
		System.out.println("");

		System.out.print("CBC Ciphertext: ");
		int[] ciphertext_cbc = CBC(plaintext_ecb_cbc_third, key_iv_ecb_cbc, key_iv_ecb_cbc);
		for (int i = 0; i < ciphertext_cbc.length; i++)
		{
			System.out.print(ciphertext_cbc[i] + " ");
		}
		System.out.println("");
	}
}
