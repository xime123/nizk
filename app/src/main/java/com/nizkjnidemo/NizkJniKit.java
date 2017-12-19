package com.nizkjnidemo;

/**
 * Created by xumin on 2017/9/5.
 */

public class NizkJniKit {
    static {
        System.loadLibrary("nizk");
    }


    public  static  native String getPubKey(String pbPriKey, int iPriKeyLen);
    /* 零知识证明加密
        @pbCiphertext : 输出参数，加密后的密文
        @piCiphertextLen : 输出参数，加密后的密文长度
        @pbPubKey : 用户的公钥，通过NIZK_KeyGen生成
        @iPubKeyLen : 公钥长度
        @pbMessage : 待加密的消息明文
        @iMessageLen : 待加密消息明文的长度
        @pbRandom : 随机数，随机生成32字节
        @iRandomLen : 随机数长度，固定32字节
    */
    public  static  native String NIZK_Encryption( String pbPriKey, int iPubKeyLen,String pbMessage, int iMessageLen);


    /* 零知识证明解密
        @pbMessage : 输出参数，解密后的消息明文
        @piMessageLen : 输出参数，解密后的消息明文长度
        @pbCiphertext : 加密后的密文，通过NIZK_Encryption生成
        @iCiphertextLen : 密文长度
        @pbPriKey : 用户的私钥
        @iPriKeyLen : 私钥长度
    */

    public  static  native String NIZK_Decryption(String pbCiphertext, int iCiphertextLen, String pbPriKey, int iPriKeyLen,String filePath,int iRange);


    /* 生成零知识证明
        @pbPai : 输出参数，生成的证明密文
        @piPaiLen : 生成的证明密文长度
        @pbTraAPubCipher : 转出账户加密的转出金额密文，是用NIZK_Encryption加密的结果
        @piTraAPubcipherLen : 转出账户加密的转出金额密文长度
        @pbTraBPubCipher : 转入账户加密的转入金额密文，是用NIZK_Encryption加密的结果
        @piTraBPubCipherLen : 转入账户加密的转入金额密文长度
        @pbBalAPubCipher : 转出账户的余额密文，是用NIZK_Encryption加密的结果
        @iBalAPubCipherLen : 转出账户的余额密文长度
        @pbAPubKey : 转出账户的公钥，通过NIZK_KeyGen生成
        @pbBPubKey : 转入账户的公钥，通过NIZK_KeyGen生成
        @iPubKeyLen : 公钥长度
        @pbAPriKey : 转出账户的私钥
        @iAPriKeyLen : 转出账户私钥的长度
        @pbRandom : 随机数，随机生成32字节
        @iRandomLen : 随机数长度，固定32字节
        @pbBalance : 转出账户的余额明文
        @iBalanceLen : 转出账户余额明文的长度
        @pbTrade : 转账金额的明文
        @iTradeLen : 转账金额明文的长度
        @pbNIZKPP : 零知识证明的全局结构，通过NIZK_Setup生成
        @iNIZKPPLen : 零知识证明的全局结构长度
    */
    public  static  native String NIZK_GenProof(String pbBalAPubCipher,String pbAPubKey, String pbBPubKey, int iPubKeyLen, String pbAPriKey, int iAPriKeyLen, String pbBalance, int iBalanceLen, String pbTrade, int iTradeLen,String pbNIZKPP, int iNIZKPPLen);

    public static native int  NIZK_VerifyProof(String pbPai,  String pbBalAPubCipher,String pbTraAPubCipher, String pbTraBPubCipher,  String pbAPubKey, String pbBPubKey, String pbNIZKPP);

}
