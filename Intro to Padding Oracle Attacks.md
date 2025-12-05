# AES Encryption
AES is a block cipher, which means that its operations can only be run on a fixed amount of data at once. For AES, the block size is 16 bytes (128 bits). So in order to encrypt data, it must be exactly 16 bytes.

## Padding
Since data that needs to be encrypted commonly doesn't fit exactly within the block size of an encryption algorithm, we need to use a few tricks to make it fit, the first is padding.

The most common method of padding is called PKCS#7. With PKCS#7, extra bytes are added to the end of the message to make the length equal to 16 bytes. The value of these bytes is the same as the number of bytes added, so if 5 bytes need to be added, their value would be `\x05`.

For example if the plaintext value were `\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b`, then with the padding it would be `\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x05\x05\x05\x05\x05`.

If the final padding bytes are not all equal, then it does not comply with PKCS#7, and the system should throw a padding error. When an attacker can distinguish a “padding error” from a “valid padding but other failure,” this becomes a padding oracle. By observing which modifications cause the padding to be valid, the attacker can infer plaintext values.

## Modes of Operation
In order to encrypt more than 16 bytes, block ciphers employ what are known as modes of operation. These are methods of using AES to encrypt multiple blocks of data. The mode of operation we'll focus on here is CBC as it is a common mode that when combined with a padding oracle can allow for decrypting the plaintext.

With AES-CBC, a block's plaintext is XORed with the previous block's cipher text before encryption. This ensures that identical blocks don't result in identical ciphertexts.

This process is run backward when decrypting, and each block is decrypted, then XORed with the ciphertext of the previous block to recover the plaintext.

This creates an issue with the first block as there is no prior block to use for XORing. This is where the initialization vector (IV) comes into play. The initialization vector is used in place of the previous block of ciphertext when encrypting and decrypting the first block.

# Putting it all together
We now know everything we need to know to exploit a padding oracle issue. Since the IV is XORed against the plaintext value during decryption, and we can cause padding errors if the final bytes aren't correct, we can figure out what IV bytes are needed to result in a specific plaintext.

For example, if we are trying to decrypt a single block, we can modify the final byte of the IV, iterating through all possible bytes until the server does not return a padding error.

Once we aren't getting a padding error anymore, we know that our input has caused the plaintext to conform to PKCS#7 padding. But specifically with the last byte, we don't know if this is because the final byte is now `\x01`, or if the last two bytes happen to be `\x02\x02`. So to ensure we've found the input that will cause the plaintext to be `\x01`, we can modify the second last byte. If this reintroduces the padding error, then we know we haven't found the right value. If the server does not return a padding error, then we know that we've found the IV input, that when XORed with the plaintext results in `\x01`.

Because a property of XOR is that if `A XOR B = C`, then `A XOR C = B` and `B XOR C = A`, we can take our new IV's final byte and the padding value (`\x01` in this case), and XOR them. Then we can take the result of that and XOR it with the original IV byte, and this will result in the plaintext byte. To simplify this `plaintext[i] = original_iv[i] ^ modified_iv[i] ^ padding_valude`.

This process can be continued for the rest of the bytes. Since we now know the plaintext value of the final byte, we can calculate the IV needed to make the output of their XOR `\x02`, then cycle through bytes for the second last byte of the IV until the padding oracle disappears, and then we'll know that we've found the IV that causes the second last byte of plaintext to equal `\x02`

This process can also be continued with all blocks of the ciphertext, substituting the previous block of ciphertext in for the IV.

Once this process is finished, the full plaintext value will have been decrypted.