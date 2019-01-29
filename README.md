# AEAD_CHACHA20_POLY1305

Implemented from rtf8439

https://tools.ietf.org/html/rfc7539#section-2.5

https://tools.ietf.org/html/rfc8439

# The Poly1305-AES message-authentication code

http://cr.yp.to/mac/poly1305-20050329.pdf

Adapted from https://asecuritysite.com/encryption/poly1305

# USAGE 

$x = new AEAD_CHACHA20_POLY1305;

$poly_mac  = $x->poly($r_key , $s_key , $msg)

   o  K_LEN (key length) is 32 octets.

   o  P_MAX (maximum size of the plaintext) is 274,877,906,880 bytes, or
      nearly 256 GB.

   o  A_MAX (maximum size of the associated data) is set to 2^64-1
      octets by the length field for associated data.

   o  N_MIN = N_MAX = 12 octets.

   o  C_MAX = P_MAX + tag length = 274,877,906,896 octets.


for the nonce 

	A 96-bit nonce -- different for each invocation with the same key
	
	Some protocols may have unique per-invocation inputs that are not 96
	   bits in length.  For example, IPsec may specify a 64-bit nonce.  In
	   such a case, it is up to the protocol document to define how to
	   transform the protocol nonce into a 96-bit nonce, for example, by
	   concatenating a constant value.
 
32-bit fixed-common part = Constant = '07000000' from rtf8439


$cipher    = $x->chacha20_aead_encrypt($aad, $Key, $Iv, '07000000', $plaintext)

	$cipher returns ciphered text + tag in hex, so tag = substr(cipher,-32) and cipher = substr(cipher,0,-32)
 
$plaintext = $x->chacha20_aead_decrypt($aad, $Key, $Iv, '07000000', $cipher)

	$cipher should have tag appended
	

# TEST VECTORS

$x->test_poly1305();

$x->test_Chacha();

$x->test_AEAD_CHACHA20_POLY1305();
	
# License

This code is placed in the public domain.
