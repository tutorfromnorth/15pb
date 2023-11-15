#pragma once
#define DLL_EXPORT extern "C" __declspec(dllexport)
/*
* ��ģ������x64����
* ��ģ���ʵ��AES��RSA�ӽ��ܣ����Խ�ȡ����ͼƬ����ͼƬ����ֻ����bmp
* Ҳ���Լ���32λMD5
*/

#define AES_KEY_IV_SIZE 16
#define ALIGN_AES_SIZE(size) (size% AES_KEY_IV_SIZE ? \
        size / AES_KEY_IV_SIZE + 1 : size / AES_KEY_IV_SIZE)* AES_KEY_IV_SIZE


/*
   ��������
*/
typedef const unsigned char* PCUCHAR;
typedef unsigned char* PUCHAR;
typedef unsigned char UCHAR;

/*
	������������
*/

/*
	���ã��������ݵ�MD5ֵ
	������
		����1��Ҫ����MD5�����ݵ�ַ
		����2���洢MD5ֵ�Ļ�������ַ
	����ֵ����
	��  ע����
*/
DLL_EXPORT void GetMD5(const char* data, char* out32);


/*
	���ã�AES����
	������
		����1�����������ݵ�ַ
		����2�������ֽڴ�С
		����3���洢���ܺ�����Ļ�����,��С�ǲ���2����16������ֵ
	����ֵ���ɹ������棬�����
	��  ע��AES���ܷ�ʽ��CBCģʽ
*/
DLL_EXPORT bool AESEncrpty(PCUCHAR pData, size_t dataSize, PUCHAR pOut);


/*
	���ã�AES����
	������
		����1�����������ݵ�ַ
		����2�������ֽڴ�С
		����3���洢���ܺ�����ݻ�����,��С�ǲ���2����16������ֵ
	����ֵ���ɹ������棬�����
	��  ע��AES���ܷ�ʽ��CBCģʽ
*/
DLL_EXPORT bool AESDecrpty(PCUCHAR pData, size_t dataSize, PUCHAR pOut);


/*
	���ã�AES����
	������
		����1���������ļ�·��
		����2�����ܺ�����ļ�·��
	����ֵ���ɹ������棬�����
	��  ע��AES���ܷ�ʽ��CBCģʽ
*/
DLL_EXPORT bool AESEncrptyFile(char* inPath, char* outPath);


/*
	���ã�AES����
	������
		����1���������ļ�·��
		����2�����ܺ�����ļ�·��
	����ֵ���ɹ������棬�����
	��  ע��AES���ܷ�ʽ��CBCģʽ
*/
DLL_EXPORT bool AESDecrptyFile(char* inPath, char* outPath);


/*
	���ã���ʼ��AES��Կ
	��������
	����ֵ����
	��  ע��ʹ��AES�ӽ���ʱ�������ȵ��ó�ʼ������
*/
DLL_EXPORT void InitAES();


/*
	���ã���ʼ��AES��Կ
	������
		����1��16λ��Կ
		����2��16λIV
	����ֵ����
	��  ע��ʹ��AES�ӽ���ʱ�������ȵ��ó�ʼ������
*/
DLL_EXPORT void SetAESKeyAndIv(UCHAR* pKey, UCHAR* pIv);


/*
	���ã���ȡAES��Կֵ
	��������
	����ֵ��AES��Կ��ַ
	��  ע��AES���ܷ�ʽ��CBCģʽ
*/
DLL_EXPORT PUCHAR GetAESKey();


/*
	���ã���ȡAES��IVֵ
	��������
	����ֵ��AES��IV��ַ
	��  ע��AES���ܷ�ʽ��CBCģʽ
*/
DLL_EXPORT PUCHAR GetAESIv();


/*
	���ã���ʼ��RSA��Կ
	��������
	����ֵ����
	��  ע��ʹ��RSA�ӽ���ʱ�ٶȺ������������ݲ��˳���100�ֽ�
*/
DLL_EXPORT bool InitRSA();


/*
	���ã��ͷ�RSAռ�õ��ڴ�
	��������
	����ֵ����
	��  ע������RSA��ʱ��һ��Ҫ���ô˺�������Ȼ������ڴ�й¶
			���⣬���û����InitRSA()���Ͳ���Ҫ���ô˺���
*/
DLL_EXPORT void ReleaseRSA();


/*
	���ã���ȡRSA˽Կ
	������
		����1���洢˽Կ�Ļ�������ַ
	����ֵ��˽Կ���ֽڴ�С
	��  ע�������Ǹ�����ָ��
*/
DLL_EXPORT int GetPriBuf(PUCHAR* pPrivate);


/*
	���ã�����RSA˽Կ
	������
		����1���洢˽Կ�Ļ�������ַ
		����2��˽Կ��С
	����ֵ����
	��  ע����
*/
DLL_EXPORT void SetPriKey(PUCHAR pPrivate, int nSize);

/*
	���ã���ȡRSA��Կ
	������
		����1���洢��Կ�Ļ�������ַ
	����ֵ����Կ���ֽڴ�С
	��  ע�������Ǹ�����ָ��
*/
DLL_EXPORT int GetPubBuf(PUCHAR* pPublic);


/*
	���ã�����RSA��Կ
	������
		����1���洢��Կ�Ļ�������ַ
		����2����Կ��С
	����ֵ����
	��  ע����
*/
DLL_EXPORT void SetPubKey(PUCHAR pPublic, int nSize);


/*
	���ã�RSA����
	������
		����1�����������ݵ�ַ
		����2�������ֽڴ�С
		����3���洢���ܺ�������ֽڴ�С
	����ֵ���ɹ��������ĵ�ַ�����򷵻�0
	��  ע����
*/
DLL_EXPORT PUCHAR RSAEncrypt(PUCHAR pBuf, int nBufSize, int* outSize);


/*
	���ã�RSA����
	������
		����1�����������ݵ�ַ
		����2�������ֽڴ�С
		����3���洢���ܺ�������ֽڴ�С
	����ֵ���ɹ��������ĵ�ַ�����򷵻�0
	��  ע�����ܺ�����Ĵ�С��һ������ԭʼ���ݵ���ʵ��С
*/
DLL_EXPORT PUCHAR RSADecrypt(PUCHAR pBuf, int nBufSize, int* outSize);


/*
	���ã���ȡ�����ͼ
	������
		����1����ͼ�洢·����Ĭ�ϴ洢�ڵ�ǰĿ¼�У�������default.bmp
	����ֵ����
	��  ע����
*/
DLL_EXPORT void GetDesktopScreenPic(PCUCHAR pPath = NULL);


/*
	���ã���ȡ�����ͼ
	��������
	����ֵ������ͼƬ�ڴ��ַ
	��  ע��ͼƬ������bmp����֧����������
*/
DLL_EXPORT PUCHAR Screenshot();


/*
	���ã���ȡ�����ͼ�ֽڴ�С
	��������
	����ֵ������ͼƬ�ֽڴ�С
	��  ע��ͼƬ������bmp����֧����������
*/
DLL_EXPORT unsigned int GetScreenPicSize();



/*
	���ã��ͷŽ�ͼռ�õ��ڴ���Դ
	��������
	����ֵ����
	��  ע������ͼ��Ҫ�ͷţ���Ȼ������ڴ�й¶
*/
DLL_EXPORT void ReleasePic();








