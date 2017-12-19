#include <android/log.h>
#include "nizk.h"

PFC pfc(AES_SECURITY, NULL, PPByte);

void print_hex(const char * msg, const void * buf, size_t len)
{
    string str = "0x";
    char hexchar[3] = { 0 };
    for (size_t i=0; i<len; ++i)
    {
        snprintf(hexchar, 3, "%02x", ((unsigned char*)buf)[i]);
        str += hexchar;
    }
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","%s buf = %s len =%d", msg, str.c_str(), len);
}

/*
Function: Generates the public parameters
Input: the sign key
Output: the public parameters
*/
void NIZK_Setup(BYTE* pbNIZKPP, int* piNIZKPPLen, BYTE* pbPriKey, int iPriKeyLen)
{
	/**************/
	G1 g1, tmp_G1;
	G2 h_s, g2;
	GT tmp_GT;
	Big tmp_Big, prikey;
	int i, n;
	/**************/
	n = 1024;
	g1 = pfc.getg1();
	g2 = pfc.getg2();
	pfc.precomp_for_mult(g1);//for precomupte
	pfc.precomp_for_pairing(g2);

	prikey = from_binary(iPriKeyLen, (char*)pbPriKey);//%pfc.order();
	h_s = pfc.mult(g2, prikey);
	h_s.G2_To_Bytes(pbNIZKPP);
	for (i = 0; i < n; i++)
	{
		tmp_Big = ((Big)i + prikey)%pfc.order();
		tmp_Big = inverse(tmp_Big, pfc.order());
		tmp_G1 = pfc.mult(g1, tmp_Big);
		tmp_G1.G1_To_Bytes(pbNIZKPP+4*pfc.bytes_per_big+i*14*pfc.bytes_per_big);
		tmp_GT = pfc.pairing(g2, tmp_G1);
		tmp_GT.GT_To_Bytes(pbNIZKPP+4*pfc.bytes_per_big+i*14*pfc.bytes_per_big+2*pfc.bytes_per_big);
		cout<<i<<endl;
	}
	*piNIZKPPLen = 4*pfc.bytes_per_big+n*14*pfc.bytes_per_big;
}
/**
Function: the method generates a public key pair 
Input: the secret key pair (pBx1, pBx2)
Output: the public key pair (pPointX1, pPointX2)
**/
void NIZK_KeyGen(BYTE* pbPubKey, int* piPubKeyLen, BYTE* pbPriKey, int iPriKeyLen)
{
	/**************/
	Big x1, x2;
	G1 point, g1;
	/**************/
	if (2*pfc.bytes_per_big != iPriKeyLen)
	{
		cout<<"the length of PriKey is error!"<<endl;
		return;
	}
	x1 = from_binary(pfc.bytes_per_big, (char*)pbPriKey);
	x2 = from_binary(pfc.bytes_per_big, (char*)(pbPriKey+pfc.bytes_per_big));
	g1 = pfc.getg1();
	pfc.precomp_for_mult(g1);
	point  = pfc.mult(g1, x1);
	point.G1_To_Bytes(pbPubKey);
	point = pfc.mult(g1, x2);
	point.G1_To_Bytes(pbPubKey+2*pfc.bytes_per_big);
	*piPubKeyLen = 4*pfc.bytes_per_big;
}
/*
Function: this method encrypts the message
Input: the public key pair (PointX1, PointX2), the message (message), the secure random (y_1, y_2), the public parameters (pp)
Output: the ciphertext (pCiphertext)
*/

void NIZK_Encryption(BYTE* pbCiphertext, int* piCiphertextLen, BYTE* pbPubKey, int iPubKeyLen, BYTE* pbMessage, int iMessageLen, BYTE* pbRandom, int iRandomLen)
{
    print_hex("pbPubKey", pbPubKey, iPubKeyLen);
    print_hex("pbMessage", pbMessage, iMessageLen);

	G1 g1, h, PubKey_X1, PubKey_X2;
	G1 C1, C2;
	int m;
	Big y_1, y_2, tmp;

	g1 = pfc.getg1();
	h = pfc.geth();
	if (iPubKeyLen != 4*pfc.bytes_per_big)
	{
		cout<<"the length of Pubkey is error!"<<endl;
		return;
	}
	PubKey_X1 = pfc.bytes_to_g1(pbPubKey);
	PubKey_X2 = pfc.bytes_to_g1(pbPubKey+2*pfc.bytes_per_big);
	m = ByteToInt(pbMessage, 0);
	if (m < 0)
	{
		cout<<"the message is invalid!"<<endl;
		return;
	}
	if (iRandomLen != 2*pfc.bytes_per_big)
	{
		cout<<"the length of random is error!"<<endl;
		return;
	}
	y_1 = from_binary(pfc.bytes_per_big, (char*)pbRandom);
	y_2 = from_binary(pfc.bytes_per_big, (char*)(pbRandom+pfc.bytes_per_big));

	C1 = pfc.mult(PubKey_X1, y_1);
	C1.G1_To_Bytes(pbCiphertext);
	C2 = pfc.mult(PubKey_X2, y_2);
	C2.G1_To_Bytes(pbCiphertext + 2*pfc.bytes_per_big);

	tmp = (y_1 + y_2)%pfc.order();
	C1 = pfc.mult(g1, tmp);
	C2 = pfc.mult(h, (Big)m);
	C1 = C1 + C2;
	C1.G1_To_Bytes(pbCiphertext + 4*pfc.bytes_per_big);
	*piCiphertextLen = 6*pfc.bytes_per_big;
	return;
}

/**********
function: Homomorphic addition of ciphertext 
***********************/
void NIZK_APubCipherAdd(BYTE* pbResult, int* piResultLen, BYTE* pbAPubCipher1, BYTE* pbAPubCipher2, int iAPubCipherLen)
{
	G1 point1, point2;
	if (iAPubCipherLen != 6*pfc.bytes_per_big)
	{
		cout<<"the length of ciphertext is invalid!"<<endl;
		return;
	}
	//C1*C1
	point1 = pfc.bytes_to_g1(pbAPubCipher1);//(pbCiphertextA);
	point2 = pfc.bytes_to_g1(pbAPubCipher2);//(pbCiphertextB);
	point1 = point1 + point2;
	point1.G1_To_Bytes(pbResult);
	//C2*C2
	point1 = pfc.bytes_to_g1(pbAPubCipher1+2*pfc.bytes_per_big);//(pbCiphertextA+2*bytes_per_big);
	point2 = pfc.bytes_to_g1(pbAPubCipher2+2*pfc.bytes_per_big);//(pbCiphertextB+2*bytes_per_big);
	point1 = point1 + point2;
	point1.G1_To_Bytes(pbResult+2*pfc.bytes_per_big);
	//C3*C3
	point1 = pfc.bytes_to_g1(pbAPubCipher1+4*pfc.bytes_per_big);//(pbCiphertextA+4*bytes_per_big);
	point2 = pfc.bytes_to_g1(pbAPubCipher2+4*pfc.bytes_per_big);//(pbCiphertextB+4*bytes_per_big);
	point1 = point1 + point2;
	point1.G1_To_Bytes(pbResult+4*pfc.bytes_per_big);
	//set length
	*piResultLen = iAPubCipherLen;
	return;
}
/**********
functiong: Homomorphic subtraction of ciphertext 
***********************/
void NIZK_APubCipherSub(BYTE* pbResult, int* piResultLen, BYTE* pbAPubCipher1, BYTE* pbAPubCipher2, int iAPubCipherLen)
{
	G1 point1, point2;

	if (iAPubCipherLen != 6*pfc.bytes_per_big)
	{
		cout<<"the length of ciphertext is invalid!"<<endl;
		return;
	}
	//C1/C1
	point1 = pfc.bytes_to_g1(pbAPubCipher1);//(pbCiphertextA);
	point2 = pfc.bytes_to_g1(pbAPubCipher2);//(pbCiphertextB);
	point1 = point1 + (-point2);
	point1.G1_To_Bytes(pbResult);
	//C2/C2
	point1 = pfc.bytes_to_g1(pbAPubCipher1+2*pfc.bytes_per_big);
	point2 = pfc.bytes_to_g1(pbAPubCipher2+2*pfc.bytes_per_big);
	point1 = point1 + (-point2);
	point1.G1_To_Bytes(pbResult+2*pfc.bytes_per_big);
	//C3/C3
	point1 = pfc.bytes_to_g1(pbAPubCipher1+4*pfc.bytes_per_big);
	point2 = pfc.bytes_to_g1(pbAPubCipher2+4*pfc.bytes_per_big);
	point1 = point1 + (-point2);
	point1.G1_To_Bytes(pbResult+4*pfc.bytes_per_big);
	//Set length
	*piResultLen = iAPubCipherLen;
	return;
}

/*
Function: this method deccrypts the ciphertext
Input: the public key pair (x1, x2), the ciphertext (ciphertext),  the public parameters (pp)
Output: the message (-1: the length is error; 0: decryption is fail, 1:decryption is successful)
*/
void NIZK_Decryption(BYTE* pbMessage, int* piMessageLen, BYTE* pbCiphertext, int iCiphertextLen, BYTE* pbPriKey, int iPriKeyLen, char* pcfilename, int iRandge)
{
    print_hex("pbCiphertext", pbCiphertext, iCiphertextLen);
    print_hex("pbPriKey", pbPriKey, iPriKeyLen);

	Big x1, x2, inv;
	G1 C1, tmp_C1, C2, tmp_C2, C3, tmp_C3;
	NIZK_List table[1024];
	int i,result;
	int flag = 0;
	if (iPriKeyLen != 2*pfc.bytes_per_big)
	{
		cout<<"the length of prikey is error"<<endl;
		return;
	}
	if (iCiphertextLen != 6*pfc.bytes_per_big)
	{
		cout<<"the length of ciphertext is error"<<endl;
		return;
	}
	x1 = from_binary(pfc.bytes_per_big, (char*)pbPriKey);
	x2 = from_binary(pfc.bytes_per_big, (char*)(pbPriKey+pfc.bytes_per_big));

	inv = inverse(x1, pfc.order());
	C1 = pfc.bytes_to_g1(pbCiphertext);//C1
	tmp_C1 = pfc.mult(C1, inv);

	inv = inverse(x2, pfc.order());
	C2 = pfc.bytes_to_g1(pbCiphertext+2*pfc.bytes_per_big);//C2
	tmp_C2 = pfc.mult(C2, inv);

	tmp_C3 = tmp_C1 + tmp_C2;
	tmp_C3 = -tmp_C3;
	C3 = pfc.bytes_to_g1(pbCiphertext + 4*pfc.bytes_per_big);//C3;
	tmp_C3 = C3 + tmp_C3;
	for (i =0; i< iRandge; i++)
	{
		flag = NIZK_ReadList(table, 1024, i*1024, pcfilename);
		if (flag == 0)
		{
			cout<<"precompute data does not exist! the decryption operation is over!"<<endl;
			break;
		}
		result =NIZK_GetMessage(table, i, 1024, tmp_C3);
		if (result!=0)
		{
			IntToByte(pbMessage, result);
			*piMessageLen = 4;
			break;
		}
		cout<<"times = "<<i<<endl;
	}
	pbMessage = NULL;
	piMessageLen = 0;//set length
	return;
}


/*
Function: generate the proof
Input: the ciphertexts, the public keys, the public parameters
Output: the proof 
*/
void NIZK_GenProof(BYTE* pbPai, int* piPaiLen, BYTE* pbTraAPubCipher, int* piTraAPubcipherLen, BYTE* pbTraBPubCipher, int* piTraBPubCipherLen, BYTE* pbBalAPubCipher, int iBalAPubCipherLen, BYTE* pbAPubKey, BYTE* pbBPubKey, int iPubKeyLen, BYTE* pbAPriKey, int iAPriKeyLen, BYTE* pbRandom, int iRandomLen, BYTE* pbBalance, int iBalanceLen, BYTE* pbTrade, int iTradeLen, BYTE* pbNIZKPP, int iNIZKPPLen)
{
	int t_0 ,t_1,t_2;//t
	int t_00, t_11,t_22;//t' = t_a -t
	int tmp;
	Big random_Big;
	Big tmp_Big;
	Big tmp1_Big, tmp2_Big, sum_Big;
	Big e, e1;
	Big arr_Big[4];

	Big r_1, r_2;
	Big v_0, v_1, v_2, v_00, v_11, v_22;
	Big s_0, s_1, s_2;
	Big w_0, w_1, w_2;
	Big l,k;
	Big q_0, q_1, q_2;
	Big m_0, m_1, m_2;
	Big z_0, e_0;
	Big z_l, z_k;
	Big x1, x2;

	G1 h, g_1;
	GT g_t;
	Big y_1, y_2;

	G1 arr_G1[4];
	G1 tmp1_G1, tmp2_G1, tmp3_G1, tmp_G1;
	G1 point1, point2;
	G1 alpha;
	G1 sigma;
	GT T;
	GT tmp_GT;
	Big cof1 = 1<<10;
	Big cof2 = 1<<20;
////////////////////////////
	//随机数不足（26*32）
	if (iRandomLen <26*pfc.bytes_per_big)
	{
		cout<<"the length of random is error!"<<endl;
		return;
	}
	/*产生交易额密文(A公钥, B公钥)*/
	NIZK_Encryption(pbTraAPubCipher, piTraAPubcipherLen, pbAPubKey, iPubKeyLen, pbTrade, iTradeLen, pbRandom+24*pfc.bytes_per_big, 2*pfc.bytes_per_big);
	NIZK_Encryption(pbTraBPubCipher, piTraBPubCipherLen, pbBPubKey, iPubKeyLen, pbTrade, iTradeLen, pbRandom+24*pfc.bytes_per_big, 2*pfc.bytes_per_big);

	//y1
	y_1= from_binary(pfc.bytes_per_big, (char*)(pbRandom+24*pfc.bytes_per_big));
	y_2 = from_binary(pfc.bytes_per_big, (char*)(pbRandom+25*pfc.bytes_per_big));
	h = pfc.geth();
	g_1 = pfc.getg1();
	g_t = pfc.getgt();
	//余额不足
	if (ByteToInt(pbBalance, 0)<0||ByteToInt(pbTrade, 0)<0)
	{
		cout<<"the input is error!"<<endl;
		return;
	}
	//余额大于交易额
	if (ByteToInt(pbBalance, 0)<ByteToInt(pbTrade, 0))
	{
		cout<<"Balance is not enough!"<<endl;
		return;
	}
	//
	tmp = ByteToInt(pbBalance, 0)-ByteToInt(pbTrade, 0);
	NIZK_Base_Transfer(t_0, t_1, t_2, ByteToInt(pbTrade, 0));
	NIZK_Base_Transfer(t_00, t_11, t_22, tmp);
	//R_1;
	point1 = pfc.bytes_to_g1(pbAPubKey);
	point2 = pfc.bytes_to_g1(pbBPubKey);
	tmp1_G1 = point1 + (-point2);
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom));
	r_1 = random_Big;
	tmp_G1 = pfc.mult(tmp1_G1, r_1);
	tmp_G1.G1_To_Bytes(pbPai);
	//R_2;
	point1 = pfc.bytes_to_g1(pbAPubKey+2*pfc.bytes_per_big);
	point2 = pfc.bytes_to_g1(pbBPubKey+2*pfc.bytes_per_big);
	tmp2_G1 = point1 + (-point2);//XA2-XB2;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+pfc.bytes_per_big));
	r_2 = random_Big;
	tmp2_G1 = pfc.mult(tmp2_G1, r_2);
	tmp2_G1.G1_To_Bytes(pbPai+2*pfc.bytes_per_big);
	//V_j
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+2*pfc.bytes_per_big));
	v_0 = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+3*pfc.bytes_per_big));
	v_1 = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+4*pfc.bytes_per_big));
	v_2 = random_Big;
	//V0
	sigma = pfc.bytes_to_g1(pbNIZKPP+4*pfc.bytes_per_big+ t_0*14*pfc.bytes_per_big);
	tmp1_G1 = pfc.mult(sigma, v_0);
	tmp1_G1.G1_To_Bytes(pbPai+4*pfc.bytes_per_big);
	//V1
	sigma = pfc.bytes_to_g1(pbNIZKPP+4*pfc.bytes_per_big+ t_1*14*pfc.bytes_per_big);
	tmp1_G1 = pfc.mult(sigma, v_1);
	tmp1_G1.G1_To_Bytes(pbPai+6*pfc.bytes_per_big);
	//V2
	sigma = pfc.bytes_to_g1(pbNIZKPP+4*pfc.bytes_per_big+ t_2*14*pfc.bytes_per_big);
	tmp1_G1 = pfc.mult(sigma, v_2);
	tmp1_G1.G1_To_Bytes(pbPai+8*pfc.bytes_per_big);
	//V_j'
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+5*pfc.bytes_per_big));
	v_00 = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+6*pfc.bytes_per_big));
	v_11 = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+7*pfc.bytes_per_big));
	v_22 =  random_Big;
	//V00
	sigma = pfc.bytes_to_g1(pbNIZKPP+4*pfc.bytes_per_big+ t_00*14*pfc.bytes_per_big);
	tmp1_G1 = pfc.mult(sigma, v_00);
	tmp1_G1.G1_To_Bytes(pbPai+10*pfc.bytes_per_big);
	//V11
	sigma = pfc.bytes_to_g1(pbNIZKPP+4*pfc.bytes_per_big+ t_11*14*pfc.bytes_per_big);
	tmp1_G1 = pfc.mult(sigma, v_11);
	tmp1_G1.G1_To_Bytes(pbPai+12*pfc.bytes_per_big);
	//V22
	sigma = pfc.bytes_to_g1(pbNIZKPP+4*pfc.bytes_per_big+ t_22*14*pfc.bytes_per_big);
	tmp1_G1 = pfc.mult(sigma, v_22);
	tmp1_G1.G1_To_Bytes(pbPai+14*pfc.bytes_per_big);
	/*****************/
	//D1, D2
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+8*pfc.bytes_per_big));
	s_0 = random_Big ;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+9*pfc.bytes_per_big));
	s_1 = random_Big ;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+10*pfc.bytes_per_big));
	s_2 =random_Big ;
	//D1
	tmp1_Big = modmult(s_1, cof1, pfc.order());
	tmp2_Big = modmult(s_2, cof2, pfc.order());
	sum_Big = (s_0 + tmp1_Big + tmp2_Big) % pfc.order();
	tmp1_G1 = pfc.mult(h, sum_Big);
	sum_Big = (r_1 + r_2) %pfc.order();
	tmp1_G1 = tmp1_G1 + pfc.mult(g_1, sum_Big);
	tmp1_G1.G1_To_Bytes(pbPai+16*pfc.bytes_per_big);
	//D2
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+11*pfc.bytes_per_big));
	w_0 = random_Big ;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+12*pfc.bytes_per_big));
	w_1 = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+13*pfc.bytes_per_big));
	w_2 = random_Big;

	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+14*pfc.bytes_per_big));
	l = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+15*pfc.bytes_per_big));
	k = random_Big ;

	tmp1_Big = modmult(w_1, cof1, pfc.order());
	tmp2_Big = modmult(w_2, cof2, pfc.order());
	arr_Big[0] = (w_0 + tmp1_Big + tmp2_Big) % pfc.order();
	arr_Big[1] = l;
	arr_Big[2] = k;
	arr_Big[3] = pfc.order()-((r_1 + r_2) % pfc.order());

	arr_G1[0] = h;
	arr_G1[1] = pfc.bytes_to_g1(pbBalAPubCipher);//balanceC.C_1;
	arr_G1[2] = pfc.bytes_to_g1(pbBalAPubCipher+2*pfc.bytes_per_big);//balanceC.C_2;
	arr_G1[3] = g_1;
	tmp1_G1 = pfc.multn(4, arr_Big, arr_G1);
	tmp1_G1.G1_To_Bytes(pbPai+18*pfc.bytes_per_big);
	/////a
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+16*pfc.bytes_per_big));
	q_0 = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+17*pfc.bytes_per_big));
	q_1 = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+18*pfc.bytes_per_big));
	q_2 = random_Big;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+19*pfc.bytes_per_big));
	m_0 = random_Big ;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+20*pfc.bytes_per_big));
	m_1 = random_Big ;
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+21*pfc.bytes_per_big));
	m_2 = random_Big;
	//a0
	tmp_Big = pfc.order() - modmult(s_0, v_0, pfc.order());
	T = pfc.bytes_to_gt(pbNIZKPP+4*pfc.bytes_per_big+ t_0*14*pfc.bytes_per_big + 2*pfc.bytes_per_big);
	tmp_GT = pfc.power(T, tmp_Big)*pfc.power(g_t, q_0);
	tmp_GT.GT_To_Bytes(pbPai+20*pfc.bytes_per_big);
	//a1
	tmp_Big = pfc.order() - modmult(s_1, v_1, pfc.order());
	T = pfc.bytes_to_gt(pbNIZKPP+4*pfc.bytes_per_big+ t_1*14*pfc.bytes_per_big + 2*pfc.bytes_per_big);
	tmp_GT = pfc.power(T, tmp_Big)*pfc.power(g_t, q_1);
	tmp_GT.GT_To_Bytes(pbPai+32*pfc.bytes_per_big);
	//a2
	tmp_Big = pfc.order() - modmult(s_2, v_2, pfc.order());
	T = pfc.bytes_to_gt(pbNIZKPP+4*pfc.bytes_per_big+ t_2*14*pfc.bytes_per_big + 2*pfc.bytes_per_big);
	tmp_GT = pfc.power(T, tmp_Big)*pfc.power(g_t, q_2);
	tmp_GT.GT_To_Bytes(pbPai+44*pfc.bytes_per_big);
	//a00
	tmp_Big = pfc.order() - modmult(w_0, v_00, pfc.order());
	T = pfc.bytes_to_gt(pbNIZKPP+4*pfc.bytes_per_big+ t_00*14*pfc.bytes_per_big + 2*pfc.bytes_per_big);
	tmp_GT = pfc.power(T, tmp_Big)*pfc.power(g_t, m_0);
	tmp_GT.GT_To_Bytes(pbPai+56*pfc.bytes_per_big);
	//a11
	tmp_Big = pfc.order() - modmult(w_1, v_11, pfc.order());
	T = pfc.bytes_to_gt(pbNIZKPP+4*pfc.bytes_per_big+ t_11*14*pfc.bytes_per_big + 2*pfc.bytes_per_big);
	tmp_GT = pfc.power(T, tmp_Big)*pfc.power(g_t, m_1);
	tmp_GT.GT_To_Bytes(pbPai+68*pfc.bytes_per_big);
	//a22
	tmp_Big = pfc.order() - modmult(w_2, v_22, pfc.order());
	T = pfc.bytes_to_gt(pbNIZKPP+4*pfc.bytes_per_big+ t_22*14*pfc.bytes_per_big + 2*pfc.bytes_per_big);
	tmp_GT = pfc.power(T, tmp_Big)*pfc.power(g_t, m_2);
	tmp_GT.GT_To_Bytes(pbPai+80*pfc.bytes_per_big);
	/////////////z0.....////////////
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+22*pfc.bytes_per_big));
	e_0 = random_Big;
	//z_0
	random_Big = from_binary(pfc.bytes_per_big, (char*)(pbRandom+23*pfc.bytes_per_big));
	z_0 = random_Big ;
	//alpha
	alpha = pfc.mult(g_1, z_0) + (-pfc.mult(h, e_0));
	alpha.G1_To_Bytes(pbPai+92*pfc.bytes_per_big);
	//e
	pfc.start_hash();
	pfc.add_to_hash((char*)pbPai, 94*pfc.bytes_per_big);
	e = pfc.finish_hash_to_group()%pfc.order();
	//e1
	e1 = (e + e_0)%pfc.order();
	//z_0
	to_binary(z_0, pfc.bytes_per_big, (char*)(pbPai+94*pfc.bytes_per_big), true);
	//e_0
	to_binary(e_0, pfc.bytes_per_big, (char*)(pbPai+95*pfc.bytes_per_big), true);
	//e1
	to_binary(e1, pfc.bytes_per_big, (char*)(pbPai+96*pfc.bytes_per_big), true);
	///z_1
	tmp1_Big = (pfc.order() + r_1 - modmult(e1, y_1, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+97*pfc.bytes_per_big), true);
	//z_2
	tmp1_Big = (pfc.order() + r_2 - modmult(e1, y_2, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+98*pfc.bytes_per_big), true);
	//z_v0
	tmp1_Big  = (pfc.order() + q_0 - modmult(e1, v_0, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+99*pfc.bytes_per_big), true);
	//z_v1
	tmp1_Big = (pfc.order() + q_1 - modmult(e1, v_1, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+100*pfc.bytes_per_big), true);
	//z_v2
	tmp1_Big = (pfc.order() + q_2 - modmult(e1, v_2, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+101*pfc.bytes_per_big), true);
	//z_v00
	tmp1_Big = (pfc.order() + m_0 - modmult(e1, v_00, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+102*pfc.bytes_per_big), true);
	//z_v11
	tmp1_Big = (pfc.order() + m_1 - modmult(e1, v_11, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+103*pfc.bytes_per_big), true);
	//z_v22
	tmp1_Big = (pfc.order() + m_2 - modmult(e1, v_22, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+104*pfc.bytes_per_big), true);
	//z_t0
	tmp1_Big = (pfc.order() + s_0 - modmult(e1, (Big)t_0, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+105*pfc.bytes_per_big), true);
	//z_t1
	tmp1_Big = (pfc.order() + s_1 - modmult(e1, (Big)t_1, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+106*pfc.bytes_per_big), true);
	//z_t2
	tmp1_Big = (pfc.order() + s_2 - modmult(e1, (Big)t_2, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+107*pfc.bytes_per_big), true);
	//z_t00
	tmp1_Big = (pfc.order() + w_0 - modmult(e1, (Big)t_00, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+108*pfc.bytes_per_big), true);
	//z_t11
	tmp1_Big = (pfc.order() + w_1 - modmult(e1, (Big)t_11, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+109*pfc.bytes_per_big), true);
	//z_t22
	tmp1_Big = (pfc.order() + w_2 - modmult(e1, (Big)t_22, pfc.order())) % pfc.order();
	to_binary(tmp1_Big, pfc.bytes_per_big, (char*)(pbPai+110*pfc.bytes_per_big), true);

	x1 =from_binary(pfc.bytes_per_big, (char*)pbAPriKey);
	x2 = from_binary(pfc.bytes_per_big, (char*)(pbAPriKey+pfc.bytes_per_big));

	tmp_Big = inverse(x1, pfc.order());
	z_l = (pfc.order() + l - modmult(e1, tmp_Big, pfc.order())) % pfc.order();
	tmp_Big = inverse(x2, pfc.order());
	z_k = (pfc.order() + k - modmult(e1, tmp_Big, pfc.order())) % pfc.order();
	//z_l
	to_binary(z_l, pfc.bytes_per_big, (char*)(pbPai+111*pfc.bytes_per_big), true);
	//z_k
	to_binary(z_k, pfc.bytes_per_big, (char*)(pbPai+112*pfc.bytes_per_big), true);
	//set length
	*piPaiLen = 113*pfc.bytes_per_big;
	return;
}
/*
Function: verify the proof
Input: the proof, the ciphertexts, the secret keys, the secure random number,the public parameters
Output: yes or no 
*/
int NIZK_VerifyProof(BYTE* pbPai, int iPaiLen, BYTE* pbBalAPubCipher, BYTE* pbTraAPubCipher, BYTE* pbTraBPubCipher, int iPubCipherLen, BYTE* pbAPubKey, BYTE* pbBPubKey, int iPubKeyLen, BYTE* pbRandom, int iRandomLen, BYTE* pbNIZKPP, int iNIZKPPLen)
{
	/*****************/
	Big e, z0, e0, e1;
	Big random_Big;
	Big beta[5],d[6];
	Big z_1, z_2;
	Big z_t0, z_t1, z_t2, z_t00, z_t11, z_t22;
	Big z_l, z_k;
	Big z_v0, z_v1, z_v2, z_v00, z_v11, z_v22;

	Big tmp1_Big, tmp2_Big, sum_Big;
	Big arr5_Big[5];
	G1 arr5_G1[5];
	G1 arr6_G1[6];
	G1 test_l, test_r1, test_r2;

	G1 tmp1_G1, tmp2_G1;
	Big tmp_Big[6];
	G2 arr2_G2[2];
	G1 arr2_G1[2];
	GT a[6];
	GT l, r;
	Big cof1 = 1 <<10;
	Big cof2 = 1 << 20;

	GT gt;
	G2 h_s;
	/*****************/
	//e
	pfc.start_hash();
	pfc.add_to_hash((char*)pbPai, 94*pfc.bytes_per_big);
	e = pfc.finish_hash_to_group()%pfc.order();
	//z0,e0,e1
	z0 = from_binary(pfc.bytes_per_big, (char*)(pbPai+94*pfc.bytes_per_big));
	e0 = from_binary(pfc.bytes_per_big, (char*)(pbPai+95*pfc.bytes_per_big));
	e1 = from_binary(pfc.bytes_per_big, (char*)(pbPai+96*pfc.bytes_per_big));
	if (e1 != ((e+e0)%pfc.order()))
	{
		return E_ERROR;
	}

	arr5_G1[0] = pfc.bytes_to_g1(pbPai);//R_1
	arr5_G1[1] = pfc.bytes_to_g1(pbPai+2*pfc.bytes_per_big);//R_2
	arr5_G1[2] = pfc.bytes_to_g1(pbPai+16*pfc.bytes_per_big);//D1
	arr5_G1[3] = pfc.bytes_to_g1(pbPai+18*pfc.bytes_per_big);//D2
	arr5_G1[4] = pfc.getg1();

	random_Big = from_binary(iRandomLen, (char*)pbRandom);
	beta[0] = pfc.random_to_hash(0, random_Big);
	beta[1] = pfc.random_to_hash(1, random_Big);
	beta[2] = pfc.random_to_hash(2, random_Big);
	beta[3] = pfc.random_to_hash(3, random_Big);
	beta[4] = pfc.random_to_hash(4, random_Big);

	arr5_Big[0] = beta[0];
	arr5_Big[1] = beta[1];
	arr5_Big[2] = beta[2];
	arr5_Big[3] = beta[3];
	arr5_Big[4] = modmult(beta[4], z0, pfc.order());
	test_l = pfc.multn(5, arr5_Big, arr5_G1);
	////////////////////////////////////////////
	//R_1, R_2
	tmp1_G1 = pfc.bytes_to_g1(pbTraAPubCipher);
	tmp2_G1 = pfc.bytes_to_g1(pbTraBPubCipher);
	arr5_G1[0] = tmp1_G1 + (-tmp2_G1);//

	tmp1_G1 = pfc.bytes_to_g1(pbTraAPubCipher+2*pfc.bytes_per_big);
	tmp2_G1 = pfc.bytes_to_g1(pbTraBPubCipher+2*pfc.bytes_per_big);
	arr5_G1[1] = tmp1_G1 + (-tmp2_G1);

	tmp1_G1 = pfc.bytes_to_g1(pbAPubKey);
	tmp2_G1 = pfc.bytes_to_g1(pbBPubKey);
	arr5_G1[2] = tmp1_G1 + (-tmp2_G1);//pkA.PointX1 + (-pkB.PointX1);

	tmp1_G1 = pfc.bytes_to_g1(pbAPubKey+2*pfc.bytes_per_big);
	tmp2_G1 = pfc.bytes_to_g1(pbBPubKey+2*pfc.bytes_per_big);
	arr5_G1[3] = tmp1_G1 + (-tmp2_G1);//pkA.PointX2 + (-pkB.PointX2);
	arr5_G1[4] = pfc.geth();

	arr5_Big[0] = modmult(e1, beta[0], pfc.order());
	arr5_Big[1] = modmult(e1, beta[1], pfc.order());
	//z1,z2
	z_1 = from_binary(pfc.bytes_per_big, (char*)(pbPai+97*pfc.bytes_per_big));
	z_2 = from_binary(pfc.bytes_per_big, (char*)(pbPai+98*pfc.bytes_per_big));
	arr5_Big[2] = modmult(z_1, beta[0], pfc.order());
	arr5_Big[3] = modmult(z_2, beta[1], pfc.order());


	z_t0 = from_binary(pfc.bytes_per_big, (char*)(pbPai+105*pfc.bytes_per_big));
	z_t1 = from_binary(pfc.bytes_per_big, (char*)(pbPai+106*pfc.bytes_per_big));
	z_t2 = from_binary(pfc.bytes_per_big, (char*)(pbPai+107*pfc.bytes_per_big));
	tmp1_Big = modmult(z_t1, cof1, pfc.order());
	tmp2_Big = modmult(z_t2, cof2, pfc.order());
	sum_Big = (z_t0 + tmp1_Big + tmp2_Big) %pfc.order();
	arr5_Big[4] = modmult(sum_Big, beta[2], pfc.order());

	z_t00 = from_binary(pfc.bytes_per_big, (char*)(pbPai+108*pfc.bytes_per_big));
	z_t11 = from_binary(pfc.bytes_per_big, (char*)(pbPai+109*pfc.bytes_per_big));
	z_t22 = from_binary(pfc.bytes_per_big, (char*)(pbPai+110*pfc.bytes_per_big));
	tmp1_Big = modmult(z_t11, cof1, pfc.order());
	tmp2_Big = modmult(z_t22, cof2, pfc.order());
	sum_Big = (z_t00 + tmp1_Big + tmp2_Big) % pfc.order();
	arr5_Big[4] = (arr5_Big[4] + modmult(sum_Big, beta[3], pfc.order())) %pfc.order();
	arr5_Big[4] = (arr5_Big[4] + modmult(e0, beta[4], pfc.order())) % pfc.order();
	test_r1 = pfc.multn(5, arr5_Big, arr5_G1);
	//////
	arr6_G1[0] = pfc.bytes_to_g1(pbTraBPubCipher+4*pfc.bytes_per_big);
	arr6_G1[1] = pfc.bytes_to_g1(pbBalAPubCipher+4*pfc.bytes_per_big)+(-arr6_G1[0]);
	arr6_G1[2] = pfc.bytes_to_g1(pbBalAPubCipher);
	arr6_G1[3] = pfc.bytes_to_g1(pbBalAPubCipher+2*pfc.bytes_per_big);//balanceC.C_2;
	arr6_G1[4] = pfc.getg1();
	arr6_G1[5] = pfc.bytes_to_g1(pbPai+92*pfc.bytes_per_big);//pai.alpha;

	z_l = from_binary(pfc.bytes_per_big, (char*)(pbPai+111*pfc.bytes_per_big));
	z_k = from_binary(pfc.bytes_per_big, (char*)(pbPai+112*pfc.bytes_per_big));

	tmp_Big[0] = modmult(e1, beta[2], pfc.order());
	tmp_Big[1] = modmult(e1, beta[3], pfc.order());
	tmp_Big[2] = modmult(z_l, beta[3], pfc.order());
	tmp_Big[3] = modmult(z_k, beta[3], pfc.order());
	tmp1_Big = (z_1 + z_2) % pfc.order();
	tmp2_Big = (pfc.order() + beta[2] - beta[3]) % pfc.order();
	tmp_Big[4] = modmult(tmp1_Big, tmp2_Big, pfc.order());
	tmp_Big[5] = beta[4];
	test_r2 = pfc.multn(6, tmp_Big, arr6_G1);
	if (test_l != (test_r1+test_r2))
	{
		return R_ERROR;
	}
	///////////////////////////////
	d[0]= pfc.random_to_hash(5, random_Big);
	d[1] = pfc.random_to_hash(6, random_Big);
	d[2] = pfc.random_to_hash(7, random_Big);
	d[3] = pfc.random_to_hash(8, random_Big);
	d[4] = pfc.random_to_hash(9, random_Big);
	d[5] = pfc.random_to_hash(10, random_Big);
	arr6_G1[0] = pfc.bytes_to_g1(pbPai+4*pfc.bytes_per_big);
	arr6_G1[1] = pfc.bytes_to_g1(pbPai+6*pfc.bytes_per_big);
	arr6_G1[2] = pfc.bytes_to_g1(pbPai+8*pfc.bytes_per_big);
	arr6_G1[3] = pfc.bytes_to_g1(pbPai+10*pfc.bytes_per_big);
	arr6_G1[4] = pfc.bytes_to_g1(pbPai+12*pfc.bytes_per_big);
	arr6_G1[5] = pfc.bytes_to_g1(pbPai+14*pfc.bytes_per_big);

	z_v0 = from_binary(pfc.bytes_per_big, (char*)(pbPai+99*pfc.bytes_per_big));
	z_v1 = from_binary(pfc.bytes_per_big, (char*)(pbPai+100*pfc.bytes_per_big));
	z_v2 = from_binary(pfc.bytes_per_big, (char*)(pbPai+101*pfc.bytes_per_big));
	z_v00 = from_binary(pfc.bytes_per_big, (char*)(pbPai+102*pfc.bytes_per_big));
	z_v11 = from_binary(pfc.bytes_per_big, (char*)(pbPai+103*pfc.bytes_per_big));
	z_v22 = from_binary(pfc.bytes_per_big, (char*)(pbPai+104*pfc.bytes_per_big));

	a[0] = pfc.bytes_to_gt(pbPai+20*pfc.bytes_per_big);
	a[1] = pfc.bytes_to_gt(pbPai+32*pfc.bytes_per_big);
	a[2] = pfc.bytes_to_gt(pbPai+44*pfc.bytes_per_big);
	a[3] = pfc.bytes_to_gt(pbPai+56*pfc.bytes_per_big);
	a[4] = pfc.bytes_to_gt(pbPai+68*pfc.bytes_per_big);
	a[5] = pfc.bytes_to_gt(pbPai+80*pfc.bytes_per_big);

	tmp_Big[0] = modmult(e1, d[0], pfc.order());
	tmp_Big[1] = modmult(e1, d[1], pfc.order());
	tmp_Big[2] = modmult(e1, d[2], pfc.order());
	tmp_Big[3] = modmult(e1, d[3], pfc.order());
	tmp_Big[4] = modmult(e1, d[4], pfc.order());
	tmp_Big[5] = modmult(e1, d[5], pfc.order());

	arr2_G1[0] = pfc.multn(6, tmp_Big, arr6_G1);

	tmp_Big[0] = modmult((pfc.order()-z_t0), d[0], pfc.order());
	tmp_Big[1] = modmult((pfc.order()-z_t1), d[1], pfc.order());
	tmp_Big[2] = modmult((pfc.order()-z_t2), d[2], pfc.order());
	tmp_Big[3] = modmult((pfc.order()-z_t00), d[3], pfc.order());
	tmp_Big[4] = modmult((pfc.order()-z_t11), d[4], pfc.order());
	tmp_Big[5] = modmult((pfc.order()-z_t22), d[5], pfc.order());

	arr2_G1[1] = pfc.multn(6, tmp_Big, arr6_G1);

	tmp_Big[0] = modmult(z_v0, d[0], pfc.order());
	tmp_Big[1] = modmult(z_v1, d[1], pfc.order());
	tmp_Big[2] = modmult(z_v2, d[2], pfc.order());
	tmp_Big[3] = modmult(z_v00, d[3], pfc.order());
	tmp_Big[4] = modmult(z_v11, d[4], pfc.order());
	tmp_Big[5] = modmult(z_v22, d[5], pfc.order());

	sum_Big = (tmp_Big[0]+tmp_Big[1]+tmp_Big[2]+tmp_Big[3]+tmp_Big[4]+tmp_Big[5])%pfc.order();
	h_s = pfc.bytes_to_g2(pbNIZKPP);
	gt = pfc.getgt();
	arr2_G2[0] = h_s;
	arr2_G2[1] = pfc.getg2();//pp.g_2;
	r = pfc.multi_pairing(2, arr2_G2, arr2_G1)*pfc.power(gt, sum_Big);
	l = pfc.powern(6, d, a);
	if (l != r)
	{
		return A_ERROR;
	}
	return SUCCESSFULL;
}
/*
Function: number base conversion
*/
void NIZK_Base_Transfer(int& c0, int& c1, int& c2, int value)
{
	c0 = value & 0x3FF;//10bits
	c1 = (value>>10)&0x3FF;
	c2 = (value>>20)&0x3FF;
}
int ByteToInt(BYTE* src, int offset)
{
	int value;
	value = (int) (((unsigned int)src[offset]<<24)
				   | ((unsigned int)src[offset+1]<<16)
				   | ((unsigned int)src[offset+2] <<8)
				   | ((unsigned int)src[offset+3] ));
	return value;
}
void IntToByte(BYTE* des, int source)
{
	des[0] = (BYTE)((unsigned int)source>>24);
	des[1] = (BYTE)((unsigned int)source>>16);
	des[2] = (BYTE)((unsigned int)source>>8);
	des[3] = (BYTE)((unsigned int)source);
}


void NIZK_GenTable(NIZK_List* listtable, int begin, int length)
{
	int i = 0;
	int index =0;
	G1 h, tmp;
	h = pfc.geth();
	pfc.precomp_for_mult(h);
	for (i = begin; i < begin+length; i++)
	{
		index = i%1024;
		listtable[index].m = i;
		listtable[index].g1 = pfc.mult(h, (Big)i);
		cout<<i<<endl;
	}
}
void NIZK_SortTable(NIZK_List* listtable, int length)
{
	int i, j;
	G1 tmp_G1;
	int tmp_int;
	for (i = 1; i < length; i++)
	{
		j = i - 1;
		tmp_G1 = listtable[i].g1;
		tmp_int = listtable[i].m;
		while(j>0 && tmp_G1 <listtable[j].g1 )
		{
			listtable[j+1].m = listtable[j].m;
			listtable[j+1].g1 = listtable[j].g1;
			j--;
		}
		listtable[j+1].m = tmp_int;
		listtable[j+1].g1 = tmp_G1;
	}
}
void NIZK_Print(NIZK_List* listtable, int length)
{
	int i;
	for (i = 0; i < length; i++)
	{
		cout<<"m:"<<endl;
		cout<<listtable[i].m<<endl;
		cout<<"g1:"<<endl;
		listtable[i].g1.G1_Print();
	}
}
int NIZK_TableSearch(NIZK_List* listtable, int length, G1 dest)
{
	int low, high, mid;
	low = 0;
	high = length -1;
	while (low <= high)
	{

		mid = (low + high)/2;
		if(dest.equal(listtable[mid].g1))
		{
			if (dest == listtable[mid].g1)
			{
				return listtable[mid].m;
			}
			return -listtable[mid].m;
		}
		else if (listtable[mid].g1 > dest)
		{
			high = mid - 1;
		}
		else if (listtable[mid].g1 < dest)
		{
			low = mid + 1;
		}
		else
		{
			low = mid + 1;
		}
	}
	return -1;
}

int NIZK_GetMessage(NIZK_List* listtable, int pos, int length, G1 beta)
{
	G1 g_m, gamma;
	G1 h;
	int i,j;
	h = pfc.geth();
	g_m = pfc.mult(h, (Big)length);
	g_m = (-g_m);
	for (i = pos*1024; i < (pos*1024)+length; i++)
	{
		gamma = beta + pfc.mult(g_m, (Big)i);
        if(gamma.isZero()){
            return i*length;
        }
		j = NIZK_TableSearch(listtable, length, gamma);
		if (j != -1)
		{
			return (i*length+ j);
		}
	}
	return 0;
}

void NIZK_SaveList(NIZK_List* listtable, int length, char* filename)
{
	int i = 0;
	int j =0;
	BYTE pByte[192] = {0};
	BYTE buff[4] ={0};
	ofstream writer;
	writer.open(filename, ios::binary|ios::app);
	for (i = 0; i < length; i++)
	{
		IntToByte(buff, listtable[i].m);
		writer.write((char*)buff, 4);
		listtable[i].g1.G1_To_Bytes(pByte);
		writer.write((char*)pByte, 2*pfc.bytes_per_big);
	}
	writer.close();
}
int NIZK_ReadList(NIZK_List* listtable, int length, int pos, char* filename)
{
	int i = 0;
	ifstream reader;
	char buffer[4] = {0};
	char pByte[192] = {0};
	Big tmp;
	reader.open(filename, ios::binary);
	if (reader.fail())
	{
		return 0;
	}
	reader.seekg(pos*(2*pfc.bytes_per_big+4), ios::beg);
	for (i = 0; i < length; i++)
	{
		reader.read(buffer, 4);
		listtable[i].m = ByteToInt((BYTE*)buffer,0);
		reader.read(pByte, 2*pfc.bytes_per_big);
		listtable[i].g1 = pfc.bytes_to_g1((BYTE*)pByte);
	}
	reader.close();
	return 1;
}

