<?php
/**
The Poly1305-AES message-authentication code

http://cr.yp.to/mac/poly1305-20050329.pdf

Adapted from https://asecuritysite.com/encryption/poly1305

# USAGE 

$x = new Poly1305;

$mac = $x->poly1305($r_key , $s_key , $msg)

# TEST VECTORS

$x->test_poly1305();
	
# License

This code is placed in the public domain.
*/
	
class Poly1305
{
	/** Poly1305 */
	
	private function poly1305_key($key)
		{
		/** Prepare rkey & skey 
		Certain bits of r are required to be 0: 
		r[3], r[7], r[11], r[15] are required to 
		have their top four bits clear (i.e., to be in {0, 1, . . . , 15}), 
		and r[4], r[8], r[12] are
		required to have their bottom two bits clear (i.e., to be in {0, 4, 8, . . . , 252})
		*/
		
		$key=array_values(unpack("C*",$key));
		
		for($k=0;$k<10;$k++) $r[$k]=0;		        	        
		
		list ($rkey , $t7) = $this->poly_m($key,0,$r,array(0x1f03,0x00ff,0x1ffe,0x1f81));
		
		$rkey[9] = ($t7 >> 5) & 0x007f;
		
		for($k=0;$k<8;$k++)			
			$skey[$k] = $key[2*$k+16] & 0xff | ($key[2*$k+17] & 0xff) << 8;

		return [$rkey , $skey];	
		}

	private function poly_m($m,$mpos,$h, $and = array(0x1fff,0x1fff,0x1fff,0x1fff))
		{
		/** Add m-block to accumulator h */
		
		$t0 = $m[$mpos + 0] & 0xff | ($m[$mpos + 1] & 0xff) << 8; $h[0] += ($t0) & 0x1fff;
		$t1 = $m[$mpos + 2] & 0xff | ($m[$mpos + 3] & 0xff) << 8; $h[1] += (($t0 >> 13) | ($t1 << 3)) & 0x1fff;
		$t2 = $m[$mpos + 4] & 0xff | ($m[$mpos + 5] & 0xff) << 8; $h[2] += (($t1 >> 10) | ($t2 << 6)) & $and[0];
		$t3 = $m[$mpos + 6] & 0xff | ($m[$mpos + 7] & 0xff) << 8; $h[3] += (($t2 >> 7) | ($t3 << 9)) & 0x1fff;
		$t4 = $m[$mpos + 8] & 0xff | ($m[$mpos + 9] & 0xff) << 8; $h[4] += (($t3 >> 4) | ($t4 << 12)) & $and[1];
		$h[5] += ($t4 >> 1) & $and[2];
		$t5 = $m[$mpos + 10] & 0xff | ($m[$mpos + 11] & 0xff) << 8; $h[6] += (($t4 >> 14) | ($t5 << 2)) & 0x1fff;
		$t6 = $m[$mpos + 12] & 0xff | ($m[$mpos + 13] & 0xff) << 8; $h[7] += (($t5 >> 11) | ($t6 << 5)) & $and[3];
		$t7 = $m[$mpos + 14] & 0xff | ($m[$mpos + 15] & 0xff) << 8; $h[8] += (($t6 >> 8) | ($t7 << 8)) & 0x1fff;
		return [$h , $t7];	
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
		return [$c , $d];	
		}
	
	private function from_130_to_128($h)
		{
		/** h to uint128 = h % 2^128 */
		
	        $h[0] = (($h[0]) | ($h[1] << 13)) & 0xffff;
	        $h[1] = (($h[1] >> 3) | ($h[2] << 10)) & 0xffff;
	        $h[2] = (($h[2] >> 6) | ($h[3] << 7)) & 0xffff;
	        $h[3] = (($h[3] >> 9) | ($h[4] << 4)) & 0xffff;
	        $h[4] = (($h[4] >> 12) | ($h[5] << 1) | ($h[6] << 14)) & 0xffff;
	        $h[5] = (($h[6] >> 2) | ($h[7] << 11)) & 0xffff;
	        $h[6] = (($h[7] >> 5) | ($h[8] << 8)) & 0xffff;
	        $h[7] = (($h[8] >> 8) | ($h[9] << 5)) & 0xffff;		
		
		return $h;
		}

	private function fullcarry($h , $g)
		{
		/** Fully carry h --> g */
		
	        $c = $h[1] >> 13;
	        $h[1] &= 0x1fff;
	        for ($i = 2; $i < 10; $i++) 
			{
			$h[$i] += $c;
			$c = $h[$i] >> 13;
			$h[$i] &= 0x1fff;
	        	}
			
	        $h[0] += ($c * 5);
	        $c = $h[0] >> 13;
	        $h[0] &= 0x1fff;
	        $h[1] += $c;
	        $c = $h[1] >> 13;
	        $h[1] &= 0x1fff;
	        $h[2] += $c;
	
	        $g[0] = $h[0] + 5;
	        $c = $g[0] >> 13;
	        $g[0] &= 0x1fff;
	        for ($i = 1; $i < 10; $i++) 
			{
			$g[$i] = $h[$i] + $c;
			$c = $g[$i] >> 13;
			$g[$i] &= 0x1fff;
	        	}
		return [$h , $g, $c];
		}
			
	private function final_modulus($g , $h, $c)
		{	
		/** Compare 'h' and 'g' :
			if h < g then h is the final modulus value
			Otherwise the final value is h - g	*/
				
	        $g[9] -= (1 << 13);
	
	        $mask = ($c ^ 1) - 1;
		
	        for ($i = 0; $i < 10; $i++) 
			$g[$i] &= $mask;
			
	        $mask = ~$mask;
		
	        for ($i = 0; $i < 10; $i++) 
			$h[$i] = ($h[$i] & $mask) | $g[$i];
			
		return $h;
		}

	private function pad($data)
		{
		/** Pad if required, adding 1 before padding */
		
		$c = strlen($data)%16;$ac = 0;		
		if ($c>0) 
			{
			$data .= chr(1).str_repeat("\0",15-$c);		
			$ac=1;
	        	}			
		return [$data , $ac];		
		}
											
	public function poly($r_key,$s_key,$data)
		{			
	        list ($rkey , $skey) = $this->poly1305_key($r_key.$s_key);		
		list ($m , $ac) = $this->pad($data);
		
		$m	= array_values(unpack("C*",$m));  
		$bytes	= sizeof($m);	
		
		for($k=0;$k<10;$k++) $h[$k]=$d[$k]=0;
	
		$mpos  = 0;	
		$hibit = 1 << 11;
		
		/** Compute h = r * m */
		
	        while ($mpos < sizeof($m)) 
			{
			list ($h , $t7) = $this->poly_m($m,$mpos,$h);
						
			if ($bytes<17 and $ac) $hibit=0;
						
			$h[9] += ($t7 >> 5) | $hibit;
			
			$c = 0;$d = array();
			list ($c , $d) = $this->mul($h,$rkey);
	
			$c = (($c << 2) + $c) | 0;
			$c = ($c + $d[0]) | 0;
			$d[0] = $c & 0x1fff;
			$c >>= 13;
			$d[1] += $c;
			
			$h = $d;
			
			$mpos += 16;$bytes -= 16;            
			}
		
		$g = array();		        
		list ($h , $g, $c) = $this->fullcarry($h , $g);
				
		$h = $this->from_130_to_128($this->final_modulus($g , $h, $c));
	
		/** Add skey */
		
		        $f = $h[0] + $skey[0];
		        $h[0] = $f & 0xffff;
		        for ($i = 1; $i < 8; $i++) 
				{
				$f = ((($h[$i] + $skey[$i]) | 0) + ($f >> 16)) | 0;
				$h[$i] = $f & 0xffff;
		        	}
		
		/** Final Mac (tag) */
		
			$mac = "";
			for ($k=0;$k<16;$k+=2)
				{
			        $mac     .= sprintf("%02x",($h[$k/2] >> 0) & 0xff);
			        $mac     .= sprintf("%02x",($h[$k/2] >> 8) & 0xff);		
				}
		
		return $mac;
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
		
		echo "Key 		".strtolower($key)."\n";
		echo "Msg 		".strtolower($msg)."\n";
		echo "Valid 		".strtolower($tag)."\n";
		echo "Computed 	".($this->poly(pack("H*",$key) ,'',pack("H*",$msg)))."\n\n";
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
	
		echo "RKey 		".strtolower($r_key)."\n";
		echo "Nonce 		".strtolower($nonce)."\n";
		echo "KAes 		".strtolower($k_aes)."\n";
		echo "Msg 		".strtolower($msg)."\n\n";
		echo "Valid 		$valid\n";
		echo "Computed 	".($this->poly(pack("H*",$r_key) , $s ,pack("H*",$msg)))."\n\n\n";
		}
	}
}

$x = new Poly1305;	

$x->test_poly1305();exit;
