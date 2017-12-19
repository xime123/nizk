#include <cstring>
#include <cstdlib>
#include "com_nizkjnidemo_NizkJniKit.h"
#include "nizk.h"
#include <arpa/inet.h>
#include <android/log.h>
#include <string>

using namespace std;
//0x1234 -> bytes

int unhex(string hex, void * dst)
{
    if (hex.size() < 2 || hex[0] != '0' || (hex[1] != 'x' && hex[1] != 'X'))
        return -1;

    const char * o = hex.c_str() + 2;
    unsigned char * d = (unsigned char *)dst;

    for(size_t i=0; i<hex.size()/2-1; ++i)
    {
        char hs[3];
        hs[0] = o[i*2];
        hs[1] = o[i*2+1];
        hs[2] = '\0';
        if(!((hs[0] >= '0' && hs[0] <= '9') || (hs[0] >= 'a' && hs[0] <= 'f') || (hs[0] >= 'A' && hs[0] <= 'F')))
            return -1;
        if(!((hs[1] >= '0' && hs[1] <= '9') || (hs[1] >= 'a' && hs[1] <= 'f') || (hs[1] >= 'A' && hs[1] <= 'F')))
            return -1;

        d[i] = strtol(hs, NULL, 16);
    }

    return 0;
}
void Set_Random(BYTE* pRandom, int length)
{
    const char * p = "1234567890";
    int i;
    srand(time(NULL));
    for (i = 0; i < length; i++)
    {
        pRandom[i] = p[rand()%10];//{7,8,6}
    }
}

void Random2(BYTE* pbRandom,  BYTE* y12, BYTE* seed)
{
    Big random_Big, tmp;
    int i = 0;
    random_Big = from_binary(pfc.bytes_per_big, (char*)seed);
    for (i = 0; i< 24; i++)
    {
        tmp = pfc.random_to_hash(i, random_Big);
        to_binary(tmp, pfc.bytes_per_big, (char*)(pbRandom+i*pfc.bytes_per_big), true);

    }
    for (i = 0; i < 64; i++)
    {
        pbRandom[24*pfc.bytes_per_big+i] = y12[i];
    }
}
string hex(const void * buf, size_t len);
int strToBinary(const char *message, unsigned char * binStr, int blen){
    int val = atoi(message);
    char valHex[50] = {0};
    snprintf(valHex, sizeof(valHex), "0x%08X", val);

    string valStr = valHex;
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","valStr=%s",valStr.c_str());

    unhex(valStr, binStr);
    string xx = hex(binStr, blen);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","binStr=%s",xx.c_str());
    return 0;
}
int binaryToStr(unsigned char *binary, int len, char *message, int mlen)
{
    string strHex = hex(binary, len);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","binaryToStrstrHex =%s",strHex.c_str());

    int strInt = ntohl(*(int*)binary);
    snprintf(message, mlen, "%d", strInt);

    return 0;
}



jstring charTojstring(JNIEnv* env, const char* pat) {
    jclass strClass = env->FindClass("java/lang/String");

    jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");

    jbyteArray bytes = env->NewByteArray(strlen(pat));

    env->SetByteArrayRegion(bytes, 0, strlen(pat), (jbyte*)pat);

    jstring encoding = env->NewStringUTF("UTF-8");

    return (jstring)env->NewObject(strClass, ctorID, bytes, encoding);
}



char* jstringToChar(JNIEnv* env, jstring jstr) {
    char* rtn = NULL;
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("UTF-8");
    jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr = (jbyteArray) env->CallObjectMethod(jstr, mid, strencode);
    jsize alen = env->GetArrayLength(barr);
    jbyte* ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0) {
        rtn = (char*) malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    env->ReleaseByteArrayElements(barr, ba, 0);
    return rtn;
}


/**
 * liao
 * @param buf
 * @param len
 * @return
 */
string hex(const void * buf, size_t len)
{
    string str = "0x";
    char hexchar[3] = { 0 };
    for (size_t i=0; i<len; ++i)
    {
        snprintf(hexchar, 3, "%02x", ((unsigned char*)buf)[i]);
        str += hexchar;
    }

    return str;
}


char* ConvertJByteaArrayToChars(JNIEnv *env, jbyteArray bytearray)
{
    char *chars = NULL;
    jbyte *bytes;
    bytes = env->GetByteArrayElements(bytearray, 0);
    int chars_len = env->GetArrayLength(bytearray);
    chars = new char[chars_len + 1];
    memset(chars,0,chars_len + 1);
    memcpy(chars, bytes, chars_len);
    chars[chars_len] = 0;

    env->ReleaseByteArrayElements(bytearray, bytes, 0);

    return chars;
}
JNIEXPORT jstring JNICALL Java_com_nizkjnidemo_NizkJniKit_getPubKey(JNIEnv *env, jclass cls, jstring jprivateKey, jint priLen){
//    /***************************/
//    BYTE pbPrikeytest[64] = {
//            0x20,0x68,0xBE,0xE9,0x98,0x5D,0xF2,0xDD,0x7A,0x7F,0xCF,0x3B,0x72,0x38,0xBE,0xD0,
//            0x94,0xCB,0x8D,0x95,0xCE,0xA5,0xAD,0x95,0x86,0xCB,0x8C,0x6B,0x6E,0x57,0x66,0x94,
//            0x19,0x12,0x6D,0xB0,0x53,0xE7,0x9F,0x8B,0x7D,0x55,0xA1,0x91,0x61,0x63,0x71,0x8E,
//            0xC0,0x0A,0x38,0x48,0x8A,0xE0,0xB2,0x21,0x78,0xF1,0xCF,0x90,0x7A,0xEE,0x17,0x71
//    };
//    int iPriKeyLen = 64;
//    BYTE pbPubKey[128] = {0};
//    int piPubKeyLen = 0;
//    /***************************/
//    NIZK_KeyGen(pbPubKey, &piPubKeyLen, pbPrikey, iPriKeyLen);
//    cout<<"length = "<< piPubKeyLen<<endl;

    BYTE pbPubKey[128] = {0};
    int piPubKeyLen = 0;

    BYTE binPrivateKey[64];
     char * pbPrikey =jstringToChar(env,jprivateKey);
    int code=unhex(pbPrikey,binPrivateKey);

    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","pri=%s, len=%d\n", pbPrikey, (int)priLen);
    NIZK_KeyGen(pbPubKey, &piPubKeyLen,  binPrivateKey, (int)priLen);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","NIZK_KeyGen DONE!");
    string ss=hex(pbPubKey, sizeof(pbPubKey));
    // string 转 char*
    char* chardata = (char *) ss.c_str();
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","string2char* %s",chardata);
    jstring   _result=charTojstring(env,chardata);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","spbPubKey=%s, piPubKeyLen=%d\n", chardata, piPubKeyLen);
//    char* char2;
//    char2= getStringFromC();
//    jstring  _result=charTojstring(env,char2);


    return _result;
  }

/*
 * Class:     com_nizkjnidemo_NizkJniKit
 * Method:    NIZK_Encryption
 * Signature: (Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_nizkjnidemo_NizkJniKit_NIZK_1Encryption(JNIEnv *env, jclass cls, jstring jpubkey , jint publen, jstring jpbmsg , jint msglen){
    BYTE pbRandom[64 + 1] = {
            0x21,0x68,0xBE,0xE9,0x98,0x5D,0xF2,0xDD,0x7A,0x7F,0xCF,0x3B,0x72,0x38,0xBE,0xD0,
            0x94,0xCB,0x8D,0x95,0xCE,0xA5,0xAD,0x95,0x86,0xCB,0x8C,0x6B,0x6E,0x57,0x66,0x94,
            0x20,0x12,0x6D,0xB0,0x53,0xE7,0x9F,0x8B,0x7D,0x55,0xA1,0x91,0x61,0x63,0x71,0x8E,
            0xC0,0x0A,0x38,0x48,0x8A,0xE0,0xB2,0x21,0x78,0xF1,0xCF,0x90,0x7A,0xEE,0x17,0x71, 0x00
    };
    int iRandomLen = 64;
    BYTE pbCiphertext[192] = {0};
    int piCiphertextLen = 0;
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","Encryption—jpubkey* %s,publen%d",jpubkey,publen);
    char* pbPubkey =jstringToChar(env,jpubkey);
    char* pbmsg =jstringToChar(env,jpbmsg);
    BYTE msgBin[4] ={0};
    strToBinary(pbmsg,msgBin,4);
    Set_Random(pbRandom, iRandomLen);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","Encryption—pbmsg* %s",pbmsg);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","Encryption—pbRandom* %s ,iRandomLen%d",(char*)pbRandom,iRandomLen);
    BYTE pbPubKeyBin[128] = {0};
    unhex(pbPubkey,pbPubKeyBin);

    NIZK_Encryption(pbCiphertext, &piCiphertextLen, pbPubKeyBin, (int)publen, msgBin,4 , pbRandom, iRandomLen);

    string ss=hex(pbCiphertext, sizeof(pbCiphertext));
    // string 转 char*
    char* chardata = (char *) ss.c_str();
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","Encryption msg=%s",chardata);
    jstring   _result=charTojstring(env,chardata);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","Encryption***** msg=%s",chardata);
    free(pbPubkey);
    free(pbmsg);
    return _result;
}

/*
 * Class:     com_nizkjnidemo_NizkJniKit
 * Method:    NIZK_Decryption
 * Signature: (Ljava/lang/String;ILjava/lang/String;I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_nizkjnidemo_NizkJniKit_NIZK_1Decryption
        (JNIEnv * env, jclass jcls, jstring jpbCiphertext, jint iCiphertextLen, jstring jpbPriKey, jint iPriKeyLen,jstring jfilename,jint jiRange){


    BYTE pbMessage[8] = {0};
    int piMessageLen = 0;

    char* pbCiphertext =jstringToChar(env,jpbCiphertext);

    BYTE pbCiphertextBin[192] = {0};
    unhex(pbCiphertext,pbCiphertextBin);

    char* pbPriKey =jstringToChar(env,jpbPriKey);
    BYTE pbPriKeyBin[64] = {0};
    unhex(pbPriKey,pbPriKeyBin);
    char* filename =jstringToChar(env,jfilename);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","Decryption_pbCiphertext* %sDecryption_pbPriKey* %s,filename=%s",pbCiphertext,pbPriKey,filename);
    NIZK_Decryption(pbMessage, &piMessageLen, pbCiphertextBin, (int)iCiphertextLen, pbPriKeyBin, (int)iPriKeyLen,filename,(int)jiRange);
    char  message[64];
    binaryToStr(pbMessage,piMessageLen,message, sizeof(message));
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","string2char* %s msglen=%d",message,piMessageLen);
    jstring   _result=charTojstring(env,message);
    return _result;
}

/*
 * Class:     com_nizkjnidemo_NizkJniKit
 * Method:    NIZK_GenProof
 * Signature: (Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;ILjava/lang/String;ILjava/lang/String;ILjava/lang/String;I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_nizkjnidemo_NizkJniKit_NIZK_1GenProof(JNIEnv * env,
                                                                         jclass jcls,
                                                                         jstring jpbBalAPubCipher,
                                                                         jstring jpbAPubKey,
                                                                         jstring jpbBPubKey,
                                                                         jint iPubKeyLen,
                                                                         jstring jpbAPriKey,
                                                                         jint iAPriKeyLen,
                                                                         jstring jpbBalance,
                                                                         jint iBalanceLen,
                                                                         jstring jpbTrade,
                                                                         jint iTradeLen,
                                                                         jstring jpbNIZKPP,
                                                                         jint iNIZKPPLen)
{

    BYTE y12[64] = {
            0x00,0x68,0xBE,0xE9,0x98,0x5D,0xF2,0xDD,0x7A,0x7F,0xCF,0x3B,0x72,0x38,0xBE,0xD0,
            0x94,0xCB,0x8D,0x95,0xCE,0xA5,0xAD,0x95,0x86,0xCB,0x8C,0x6B,0x6E,0x57,0x66,0x94,
            0x00,0x12,0x6D,0xB0,0x53,0xE7,0x9F,0x8B,0x7D,0x55,0xA1,0x91,0x61,0x63,0x71,0x8E,
            0xC0,0x0A,0x38,0x48,0x8A,0xE0,0xB2,0x21,0x78,0xF1,0xCF,0x90,0x7A,0xEE,0x17,0x71
    };

    BYTE RandomSeed[32] = {
            0x20,0x68,0xBE,0xE9,0x98,0x5D,0xF2,0xDD,0x7A,0x7F,0xCF,0x3B,0x72,0x38,0xBE,0xD0,
            0x94,0xCB,0x8D,0x95,0xCE,0xA5,0xAD,0x95,0x86,0xCB,0x8C,0x6B,0x6E,0x57,0x66,0x94
    };

    BYTE pbPai[3616] = {0};
    int piPaiLen = 0;







    BYTE pbTraBPubCipherBin[192] = {0};
    int piTraBPubCipherLen=0;



    char* pbBalAPubCipher =jstringToChar(env,jpbBalAPubCipher);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","GenProofpbAPriKey* %s",pbBalAPubCipher);
    BYTE pbBalAPubCipherBin[192] = {0};
    unhex(pbBalAPubCipher,pbBalAPubCipherBin);

    char* pbAPubKey =jstringToChar(env,jpbAPubKey);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","GenProofpbAPubKey* %s",pbAPubKey);
    BYTE pbAPubKeyBin[128] = {0};
    unhex(pbAPubKey,pbAPubKeyBin);

    char* pbBPubKey =jstringToChar(env,jpbBPubKey);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","GenProofpbBPubKey* %s",pbBPubKey);
    BYTE pbBPubKeyBin[128] = {0};
    unhex(pbBPubKey,pbBPubKeyBin);


    char* pbAPriKey =jstringToChar(env,jpbAPriKey);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","GenProofpbAPriKey* %s",pbAPriKey);
    BYTE pbAPriKeyBin[64] = {0};
    unhex(pbAPriKey,pbAPriKeyBin);

    BYTE pbTraAPubCipherBin[192] = {0};
    int piTraAPubcipherLen=0;




    BYTE pbRandom[832] = {0};
    int iRandomLen = 832;
    Set_Random(pbRandom,832);

    //char  pbRandommessage[1664];
    string pbRandommessage=hex(pbRandom,832);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","GenProofpbRandommessage* %s",pbRandommessage.c_str());


    char* pbBalance =jstringToChar(env,jpbBalance);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","GenProofpbBalance* %s",pbBalance);
    BYTE pbBalanceBin[4] ={0};
    strToBinary(pbBalance,pbBalanceBin,4);

//    unsigned int lpbBalance = atoi(pbBalance); //0x04, 0x00, 0x00, 0x00 //xiaoduan
//    lpbBalance = htonl(lpbBalance); // 0x00, 0x00, 0x00, 0x04转成大端


    char* pbTrade =jstringToChar(env,jpbTrade);
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","GenProofpbTrade* %s",pbTrade);
    BYTE pbTradeBin[4] ={0};
    strToBinary(pbTrade,pbTradeBin,4);
//    unsigned int lpbTrade = atoi(pbTrade); //0x04, 0x00, 0x00, 0x00 //xiaoduan
//    lpbTrade = htonl(lpbTrade); // 0x00, 0x00, 0x00, 0x04转成大端


    char* pbNIZKPP =jstringToChar(env,jpbNIZKPP);
    BYTE pbNIZKPPBin[458880] = {0};
    unhex(pbNIZKPP,pbNIZKPPBin);

    NIZK_GenProof(pbPai, &piPaiLen,  pbTraAPubCipherBin, &piTraAPubcipherLen, pbTraBPubCipherBin, &piTraBPubCipherLen, pbBalAPubCipherBin,
                  192,  pbAPubKeyBin, pbBPubKeyBin, 128, pbAPriKeyBin, 64, pbRandom, iRandomLen,  pbBalanceBin,
                  4, pbTradeBin, 4,  pbNIZKPPBin, 458880);

    string ss=hex(pbPai, sizeof(pbPai));
    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","ss* %s",ss.c_str());
    string tra=hex(pbTraAPubCipherBin, sizeof(pbTraAPubCipherBin));
    string trb=hex(pbTraBPubCipherBin, sizeof(pbTraBPubCipherBin));
    string bal=hex(pbBalAPubCipherBin, sizeof(pbBalAPubCipherBin));
    ss.append("#");
    ss.append(tra);
    ss.append("#");
    ss.append(trb);
    ss.append("#");
    ss.append(bal);

    // string 转 char*
    char* chardata = (char *) ss.c_str();
    jstring   _result=charTojstring(env,chardata);

//
//    string pbTraAPubCipherStr=hex(pbPai, sizeof(pbTraAPubCipherBin));
//    // string 转 char*
//    char* pbTraAPubCipherdata = (char *) pbTraAPubCipherStr.c_str();
//    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","pbTraAPubCipherStr* %s",chardata);
//
//
//    string pbTraBPubCipherStr=hex(pbPai, sizeof(pbTraBPubCipherBin));
//    // string 转 char*
//    char* pbTraBPubCipherBindata = (char *) pbTraBPubCipherStr.c_str();
//    __android_log_print(ANDROID_LOG_ERROR,"HelloJni","pbTraBPubCipherBindata* %s",pbTraBPubCipherBindata);

    return _result;
}

JNIEXPORT jint JNICALL Java_com_nizkjnidemo_NizkJniKit_NIZK_1VerifyProof
        (JNIEnv * env, jclass jcls, jstring jpai, jstring jpbBalAPubCipher, jstring jpbTraAPubCipher, jstring jpbTraBPubCipher, jstring jpbAPubKey, jstring jpbBPubKey, jstring jpbNIZKPP){
    BYTE RandomSeed[32] = {
            0x20,0x68,0xBE,0xE9,0x98,0x5D,0xF2,0xDD,0x7A,0x7F,0xCF,0x3B,0x72,0x38,0xBE,0xD0,
            0x94,0xCB,0x8D,0x95,0xCE,0xA5,0xAD,0x95,0x86,0xCB,0x8C,0x6B,0x6E,0x57,0x66,0x94
    };
    int iRandomSeedLen = 32;

    char* pai =jstringToChar(env,jpai);
    BYTE paiBin[3616] = {0};
    unhex(pai,paiBin);

    char* pbBalAPubCipher =jstringToChar(env,jpbBalAPubCipher);
    BYTE pbBalAPubCipherBin[192] = {0};
    unhex(pbBalAPubCipher,pbBalAPubCipherBin);

    char* pbTraAPubCipher =jstringToChar(env,jpbTraAPubCipher);
    BYTE pbTraAPubCipherBin[192] = {0};
    unhex(pbTraAPubCipher,pbTraAPubCipherBin);

    char* pbTraBPubCipher =jstringToChar(env,jpbTraBPubCipher);
    BYTE pbTraBPubCipherBin[192] = {0};
    unhex(pbTraBPubCipher,pbTraBPubCipherBin);

    char* pbAPubKey =jstringToChar(env,jpbAPubKey);
    BYTE pbAPubKeyBin[128] = {0};
    unhex(pbAPubKey,pbAPubKeyBin);


    char* pbBPubKey =jstringToChar(env,jpbBPubKey);
    BYTE pbBPubKeyBin[128] = {0};
    unhex(pbBPubKey,pbBPubKeyBin);

    char* pbNIZKPP =jstringToChar(env,jpbNIZKPP);
    BYTE pbNIZKPPBin[458880] = {0};
    unhex(pbNIZKPP,pbNIZKPPBin);



    int ret=NIZK_VerifyProof(paiBin,3616,pbBalAPubCipherBin,pbTraAPubCipherBin,pbTraBPubCipherBin,192,pbAPubKeyBin,pbBPubKeyBin,128,RandomSeed,iRandomSeedLen,pbNIZKPPBin,458880);
    return (jint)ret;
};

