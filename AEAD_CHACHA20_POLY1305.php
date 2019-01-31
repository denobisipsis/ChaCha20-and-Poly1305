<?php
/**
AEAD_CHACHA20_POLY1305

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
*/

class AEAD_CHACHA20_POLY1305
{
	/** ChaCha20  https://tools.ietf.org/html/rfc8439  June 2018 */
	
	var $state;
			 	
      private function Left_Roll($a, $n)
		{
	        $lp = ($a << $n)        & 0xffffffff;
	        $rp = ($a >> (32 - $n)) & 0xffffffff;
	
	        return $lp | ($rp & ((1 << $n) - 1));	   	
		}
		   
      private function Quarter_Round($a,$b,$c,$d)
		{
		/** It
		   operates on four 32-bit unsigned integers */
		
		$f  = $this->state[$a];
		$g  = $this->state[$b];
		$h  = $this->state[$c];
		$i  = $this->state[$d];
				
		$f += $g; 
		$i  = $this->Left_Roll($i^$f,16);   
		$h += $i; 
		$g  = $this->Left_Roll($g^$h,12);
		
      		$f += $g; 
		$i  = $this->Left_Roll($i^$f,8);
      		$h += $i; 
		$g  = $this->Left_Roll($g^$h,7);
		      		
		$this->state[$a] = $f;
		$this->state[$b] = $g;
		$this->state[$c] = $h;
		$this->state[$d] = $i;			      				
		}

      private function inner_block($tate)
		{
		/** 
		 ChaCha20 runs 20 rounds, alternating between "column rounds" and
		   "diagonal rounds".  Each round consists of four quarter-rounds, and
		   they are run as follows.  Quarter rounds 1-4 are part of a "column"
		   round, while 5-8 are part of a "diagonal" round: 
		   */
		
		$this->Quarter_Round(0, 4, 8, 12);
		$this->Quarter_Round(1, 5, 9, 13);
		$this->Quarter_Round(2, 6, 10, 14);
		$this->Quarter_Round(3, 7, 11, 15);		
		$this->Quarter_Round(0, 5, 10, 15);
		$this->Quarter_Round(1, 6, 11, 12);
		$this->Quarter_Round(2, 7, 8, 13);
		$this->Quarter_Round(3, 4, 9, 14);		
		}

      private function chacha20_block($key, $counter, $nonce)
      		{
		/** 
		The inputs to ChaCha20 are:
				
		o  A 256-bit key, treated as a concatenation of eight 32-bit little-
		endian integers.
		
		o  A 96-bit nonce, treated as a concatenation of three 32-bit little-
		endian integers.
		
		o  A 32-bit block count parameter, treated as a 32-bit little-endian
		integer.
		
		The output is 64 random-looking bytes.
		
		The ChaCha20 state is initialized as follows:
		
		o  The first four words (0-3) are constants: 0x61707865, 0x3320646e,
		 0x79622d32, 0x6b206574.
		
		o  The next eight words (4-11) are taken from the 256-bit key by
		 reading the bytes in little-endian order, in 4-byte chunks.
		
		o  Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
		 word is enough for 256 gigabytes of data.
		
		o  Words 13-15 are a nonce, which MUST not be repeated for the same
		 key.  The 13th word is the first 32 bits of the input nonce taken
		 as a little-endian integer, while the 15th word is the last 32
		 bits.
		 
		cccccccc  cccccccc  cccccccc  cccccccc
		kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
		kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
		bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
		*/
		
		 $constants	= array(0x61707865, 0x3320646e,0x79622d32, 0x6b206574);
		 $key 		= unpack("L*",pack("H*",$key));
		 $nonce 	= unpack("L*",pack("H*",$nonce));
	         $this->state 	= array_merge($constants,$key,array($counter),$nonce);
		 
	         $initial_state = $this->state;
	         for ($i=0;$i<10;$i++)
	            	$this->inner_block($this->state);		 
		 	 		 
		 $state="";
		 for ($k=0;$k<16;$k++) 
		 	$state.=pack("L",($this->state[$k] + $initial_state[$k]) & 0xffffffff);  

	         return $state;
	         }

      public function chacha20_encrypt($key, $counter, $nonce, $plaintext)
		{
		 /** So if the provided nonce is only 64-bit, then the first 32
		       bits of the nonce will be set to a constant number.  This will
		       usually be zero, but for protocols with multiple senders it may be
		       different for each sender, but SHOULD be the same for all
		       invocations of the function with the same key by a particular
		       sender.
		       */
		       
		if (strlen($nonce)==16) 
			$nonce=str_repeat("0",8).$nonce;
					
		$encrypted_message = "";
		
		$plaintext = str_split($plaintext,64);
		
	        for ($j = 0 ; $j < sizeof($plaintext) ; $j++)
			{
			$key_stream 		= $this->chacha20_block($key, $counter+$j, $nonce);
			$encrypted_message     .= $plaintext[$j] ^ $key_stream;
	           	}	   
	        return  $encrypted_message;
	        }

      private function poly1305_key_gen($key,$nonce)
		 {		       		 		 
		 /** block[0..15] is r_key & block[16..31] s_key */

	         return substr($this->chacha20_block($key,0,$nonce),0,32);
		 }

      public function pad16($x)
      		{
	         return $x.str_repeat("\0",16-(strlen($x)%16));
         	}

      public function chacha20_aead_encrypt($aad, $key, $iv, $constant, $plaintext)
      		{
		$nonce      = $constant.$iv;
		$otk        = $this->poly1305_key_gen($key, $nonce);
		
		$ciphertext = $this->chacha20_encrypt($key, 1, $nonce, $plaintext);
		
		$aad 	    = pack("H*",$aad);		
		$mac_data   = $this->pad16($aad);
		$mac_data  .= $this->pad16($ciphertext);
		$mac_data  .= pack("P",strlen($aad));
		$mac_data  .= pack("P",strlen($ciphertext));
		
		return bin2hex($ciphertext).$this->poly($otk, "", $mac_data);
	 	}

      public function chacha20_aead_decrypt($aad, $key, $iv, $constant, $ciphertext)
      		{
		$ciphertext = pack("H*",$ciphertext);
		
		$nonce      = $constant.$iv;
		$otk        = $this->poly1305_key_gen($key, $nonce);
		
		$tag	    = substr($ciphertext,-16);
		$ciphertext = substr($ciphertext,0,-16);
		
		$aad 	    = pack("H*",$aad);		
		$mac_data   = $this->pad16($aad);
		$mac_data  .= $this->pad16($ciphertext);
		$mac_data  .= pack("P",strlen($aad));
		$mac_data  .= pack("P",strlen($ciphertext));
		
		if ($this->poly($otk, "", $mac_data)!=bin2hex($tag)) 
			die("Authentication failed");
		
		return $this->chacha20_encrypt($key, 1, $nonce, $ciphertext);
	 	}
	
	/** POLY1305 FUNCTIONS */
		 	 	 			 				
	private function poly1305_key($key)
		{
		/** Prepare rkey & skey 
		Certain bits of r are required to be 0: 
		r[3], r[7], r[11], r[15] are required to 
		have their top four bits clear (i.e., to be in {0, 1, . . . , 15})
		and r[4], r[8], r[12] are
		required to have their bottom two bits clear (i.e., to be in {0, 4, 8, . . . , 252})
		*/
	
		for($k=0;$k<10;$k++) $rkey[$k]=0;		        	        
		
		$this->poly_m(substr($key,0,16),$rkey,0,array(0x1f03,0x00ff,0x1ffe,0x1f81));
		
		$rkey[9] &= 0x007f;
		
		$skey=array_values(unpack("S*",substr($key,16)));			

		return [$rkey , $skey];	
		}
	
	private function poly_m($m, &$h, $or = 1 << 11, $and = array(0x1fff,0x1fff,0x1fff,0x1fff))
		{
		/** 
		Add m-block to accumulator h . from 128 bits to 130 in form of 160 bits 
		
		$h & 0x1fff * 10 -> 30 bits cleared
		
		(key has special and's)		
		*/
			
		$t=array_values(unpack("S*",$m));
		
		$h[0] +=   $t[0] & 0x1fff;
		$h[1] += (($t[0] >> 13) | ($t[1] << 3))  & 0x1fff;
		$h[2] += (($t[1] >> 10) | ($t[2] << 6))  & $and[0];
		$h[3] += (($t[2] >> 7)  | ($t[3] << 9))  & 0x1fff;
		$h[4] += (($t[3] >> 4)  | ($t[4] << 12)) & $and[1];
		
		$h[5] +=  ($t[4] >> 1)  & $and[2];
		
		$h[6] += (($t[4] >> 14) | ($t[5] << 2))  & 0x1fff;
		$h[7] += (($t[5] >> 11) | ($t[6] << 5))  & $and[3];
		$h[8] += (($t[6] >> 8)  | ($t[7] << 8))  & 0x1fff;
		
		$h[9] += ($t[7] >> 5)   | $or;				
		}

	private function from_130_to_128($h)
		{
		/** h to uint128 = h % 2^128 */
		
	        $h[0] = (($h[0])       | ($h[1] << 13)) & 0xffff;
	        $h[1] = (($h[1] >> 3)  | ($h[2] << 10)) & 0xffff;
	        $h[2] = (($h[2] >> 6)  | ($h[3] << 7))  & 0xffff;
	        $h[3] = (($h[3] >> 9)  | ($h[4] << 4))  & 0xffff;
	        $h[4] = (($h[4] >> 12) | ($h[5] << 1)   | ($h[6] << 14)) & 0xffff;
	        $h[5] = (($h[6] >> 2)  | ($h[7] << 11)) & 0xffff;
	        $h[6] = (($h[7] >> 5)  | ($h[8] << 8))  & 0xffff;
	        $h[7] = (($h[8] >> 8)  | ($h[9] << 5))  & 0xffff;		
		
		return $h;
		}
		
	private function mul($a, $b)
		{
		$c = 0;$d = array();
		
		for ($p=0;$p<10;$p++)
			{
			$temp = $c; $c = 0;
			for ($j=0;$j<2;$j++)
				{
				for ($k=$j*5;$k<($j+1)*5;$k++)
					{
					if ($k<($p + 1))
						$temp += $a[$k] * $b[$p-$k];
					else 
						$temp += $a[$k] * 5 * $b[10-($k-$p)];		
					}
				$c += $temp >> 13; $temp &= 0x1fff;
				}		
			$d[$p]=$temp;
			}
			
		$c    += ($c << 2) + $d[0];		
		$d[0]  = $c & 0x1fff;				
		$d[1] += $c >> 13;
				
		return $d;	
		}
			
	private function final_modulus_carry($h)
		{	
		/** Compare 'h' and 'g' :
			if h < g then h is the final modulus value
			Otherwise the final value is h - g	*/
		
		$g = array();	
	
		$c = 5;$d = 0;
					
	        for ($i = 0; $i < 10; $i++) 
			{
			$h[$i] += $d;
			$g[$i]  = $h[$i] + $c;
			$c      = $g[$i] >> 13;
			$d      = $h[$i] >> 13;
			$g[$i] &= 0x1fff;
			$h[$i] &= 0x1fff;
	        	}

	        $h[0] += $d * 5;		
	        $d     = $h[0] >> 13;
	        $h[0] &= 0x1fff;
			
	        $h[1] += $d;		
	        $d     = $h[1] >> 13;
	        $h[1] &= 0x1fff;
		
	        $h[2] += $d;
									
	        $g[9] -= 1 << 13;
		
		if ($c==0) return $h;
		
		$mask  = ($c ^ 1) - 1;

	        for ($i = 0; $i < 10; $i++) 
			$h[$i] = ($h[$i] & ~$mask) | ($g[$i] & $mask);
			
		return $h;
		}

	private function pad($data)
		{
		/** Pad if required, adding 1 before padding */
		
		$c = strlen($data)%16;$ac = 1 << 11;		
		if ($c>0) 
			{
			$data .= chr(1).str_repeat("\0",15-$c);		
			$ac = 0;
	        	}			
		return [$data , $ac];		
		}
											
	public function poly($r_key,$s_key,$data)
		{
		/** Prepare rkey & skey 
		Certain bits of r are required to be 0: 
		r[3], r[7], r[11], r[15] are required to 
		have their top four bits clear (i.e., to be in {0, 1, . . . , 15})
		and r[4], r[8], r[12] are
		required to have their bottom two bits clear (i.e., to be in {0, 4, 8, . . . , 252})
		*/				
	        list ($rkey , $skey) 	= $this->poly1305_key($r_key.$s_key);	
				
		for($k=0;$k<10;$k++) $h[$k]=0;;
		
		if ($data)
			{	
			list ($m , $ac) = $this->pad($data);
			
			$m	= str_split($m,16);  
			$blocks	= sizeof($m);	
			
			/** Compute h = r * m */
			
		        for ($k=0;$k<$blocks-1;$k++) 
				{
				$this->poly_m($m[$k],$h);
				
				$h = $this->mul($h,$rkey); 
				}
			
			$this->poly_m($m[$k],$h,$ac);
					
			$h = $this->from_130_to_128($this->final_modulus_carry($this->mul($h,$rkey)));
			}
		
		/** Add skey */
			
			$f = 0;
		        for ($i = 0; $i < 8; $i++) 
				{
				$f     = $h[$i] + $skey[$i] + ($f >> 16);
				$h[$i] = $f & 0xffff;
		        	}
		
		/** Final Mac (tag) */
		
			$mac = "";
			for ($k=0;$k<8;$k++)
				{
			        $mac     .= sprintf("%02x",($h[$k] >> 0) & 0xff);
			        $mac     .= sprintf("%02x",($h[$k] >> 8) & 0xff);		
				}
	
		return $mac;
		}
		
    public function test_AEAD_CHACHA20_POLY1305()
	{
	echo "test_AEAD_CHACHA20_POLY1305 from https://tools.ietf.org/html/rfc8439\n\n";

	  $key	 = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";	  
	  $msg	 = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
	  $iv	 = "4041424344454647";	  
	  $aad	 = "50515253c0c1c2c3c4c5c6c7";	  
	  $output= "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
	  $tag = "1ae10b594f09e26a7e902ecbd0600691";
	
	  $cipher 	 = $this->chacha20_aead_encrypt($aad, $key, $iv, '07000000', pack("H*",$msg));	 
	  $computed_tag	 = substr($cipher,-32);
	 
	echo "Key 		".strtolower($key)."\n";
	echo "Iv 	        ".strtolower($iv)."\n";
	echo "Aad 		".strtolower($aad)."\n";
	echo "Msg 		".pack("H*",strtolower($msg))."\n";
	echo "Tag 		".$tag."\n\n";
	echo "Valid 		".strtolower($output)."\n\n";
	echo "Computed 	".(substr($cipher,0,-32))."\n\n";
	echo "Computed Tag 	".$computed_tag."\n\n";
	echo "Decrypted 	".($this->chacha20_aead_decrypt($aad, $key, $iv, '07000000', $cipher))."\n\n";
	
	echo "test_AEAD_CHACHA20_POLY1305 https://bugs.chromium.org/p/chromium/issues/attachmentText?aid=1048500\n\n";
	$testvectors=explode("\n",file_get_contents("https://raw.githubusercontent.com/denobisipsis/ChaCha20-and-Poly1305/master/chacha20_poly1305_tests.txt"));

	for ($k=0;$k<sizeof($testvectors);$k+=7)
		{
		$key=trim(explode(":",$testvectors[$k])[1]);
		$iv=trim(explode(":",$testvectors[$k+1])[1]);
		$msg=trim(explode(":",$testvectors[$k+2])[1]);
		$aad=trim(explode(":",$testvectors[$k+3])[1]);
		$tag=trim(explode(":",$testvectors[$k+5])[1]);
		
		$ct=trim(explode(":",$testvectors[$k+4])[1]);

		$cipher 	 = $this->chacha20_aead_encrypt($aad, $key, $iv, '00000000', pack("H*",$msg));	 
		$computed_tag	 = substr($cipher,-32);
		$computed 	 = substr($cipher,0,-32);
	  		
		echo "Key 		".strtolower($key)."\n";
		echo "Nonce 		".strtolower($iv)."\n";
		echo "Aad 		".strtolower($aad)."\n";
		echo "Msg 		".strtolower($msg)."\n";
		echo "Valid 		".strtolower($ct)."\n";
		echo "Computed 	".$computed."\n\n";
		
		if (strtolower($ct)!=$computed) die("fail");
		}	
	echo "ok";
 	}
     
    public function test_Chacha()
    	{
	echo "chacha20 https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/tests/vectors/chacha20\n\n";
	$testvectors=explode("\n",file_get_contents("https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/tests/vectors/chacha20"));

	for ($k=0;$k<sizeof($testvectors);$k+=6)
		{
		$key=substr($testvectors[$k],0,-1);
		$nonce=substr($testvectors[$k+1],0,-1);
		$msg=substr($testvectors[$k+2],0,-1);
		$aad=substr($testvectors[$k+3],0,-1);
		
		$cipher=substr($testvectors[$k+4],0,-1);
		
		$computed = bin2hex($this->chacha20_encrypt($key, 0, $nonce, pack("H*",$msg)));
		
		echo "Key 		".strtolower($key)."\n";
		echo "Nonce 		".strtolower($nonce)."\n";
		echo "Aad 		".strtolower($aad)."\n";
		echo "Msg 		".strtolower($msg)."\n";
		echo "Valid 		".strtolower($cipher)."\n";
		echo "Computed 	".$computed."\n\n";
		
		if (strtolower($cipher)!=$computed) die("fail");
		}
	echo "ok";	    
	}
	
    public function test_poly1305()
    	{
	/** r_key & s_key joined */
	
	echo "Poly1305 https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-06\n\n";
	$testvectors=explode("\n",file_get_contents("https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/tests/vectors/poly1305"));

	for ($k=0;$k<sizeof($testvectors);$k+=4)
		{
		$key=substr($testvectors[$k],0,-1);
		$msg=substr($testvectors[$k+1],0,-1);
		$tag=substr($testvectors[$k+2],0,-1);
		
		$computed = $this->poly(pack("H*",$key) ,'',pack("H*",$msg));
		
		echo "Key 		".strtolower($key)."\n";
		echo "Msg 		".strtolower($msg)."\n";
		echo "Valid 		".strtolower($tag)."\n";
		echo "Computed 	".$computed."\n\n";
		
		if (strtolower($tag)!=$computed) die("fail");
		}
		
	/** s_key is aes-128 de nonce */	  
	
	echo "Poly1305 Examples from https://cr.yp.to/mac/poly1305-20050329.pdf\n\n";
	
	$examples=array(
	array(
	'',
	'a0f3080000f46400d0c7e9076c834403',
	'75deaa25c09f208e1dc4ce6b5cad3fbf',
	'61ee09218d29b0aaed7e154a2c5509cc',
	'dd3fab2251f11ac759f0887129cc2ee7'),
	array(
	'f3f6',
	'851fc40c3467ac0be05cc20404f3f700',
	'ec074c835580741701425b623235add6',
	'fb447350c4e868c52ac3275cf9d4327e',
	'f4c633c3044fc145f84f335cb81953de'),
	array(
	'663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136',
	'48443d0bb0d21109c89a100b5ce2c208',
	'6acb5f61a7176dd320c5c1eb2edcdc74',
	'ae212a55399729595dea458bc621ff0e',
	'0ee1c16bb73f0f4fd19881753c01cdbe'),
	array(
	'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9',
	'12976a08c4426d0ce8a82407c4f48207',
	'e1a5668a4d5b66a5f68cc5424ed5982d',
	'9ae831e743978d3a23527c7128149e3a',
	'5154ad0d2cb26e01274fc51148491f1b'));	
	
	foreach ($examples as $vector)
		{
		$msg = $vector[0];
		$r_key = $vector[1];
		$nonce = $vector[3];
		$k_aes = $vector[2];
		$valid = $vector[4];
				
		$s = openssl_encrypt(pack("H*",$nonce), 'aes-128-ecb', pack("H*",$k_aes), 1|OPENSSL_ZERO_PADDING);
		
		$computed = $this->poly(pack("H*",$r_key) , $s ,pack("H*",$msg));
	
		echo "RKey 		".strtolower($r_key)."\n";
		echo "Nonce 		".strtolower($nonce)."\n";
		echo "KAes 		".strtolower($k_aes)."\n";
		echo "Msg 		".strtolower($msg)."\n\n";
		echo "Valid 		$valid\n";
		echo "Computed 	".$computed."\n\n\n";
		
		if ($valid!=$computed) die("fail");
		}
	echo "ok";
	}
}
$x = new AEAD_CHACHA20_POLY1305;	
$x->test_AEAD_CHACHA20_POLY1305();
$x->test_poly1305();
$x->test_Chacha();
