# The Poly1305-AES message-authentication code

http://cr.yp.to/mac/poly1305-20050329.pdf

Adapted from https://asecuritysite.com/encryption/poly1305

# USAGE 

$x = new Poly1305;

$mac = $x->poly1305($r_key , $s_key , $msg)

# TEST VECTORS

$x->test_poly1305();
	
# License

This code is placed in the public domain.
