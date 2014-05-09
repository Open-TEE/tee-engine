#ifndef __OPENSLL_1_0_2_BETA_RSA_OAEP_H__
#define __OPENSLL_1_0_2_BETA_RSA_OAEP_H__

int beta_PKCS1_MGF1(unsigned char *mask, long len,
		    const unsigned char *seed, long seedlen, const EVP_MD *dgst);

int beta_RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
					   const unsigned char *from, int flen, int num,
					   const unsigned char *param, int plen,
					   const EVP_MD *md, const EVP_MD *mgf1md);

int beta_RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
					 const unsigned char *from, int flen,
					 const unsigned char *param, int plen,
					 const EVP_MD *md, const EVP_MD *mgf1md);

#endif /* __OPENSLL_1_0_2_BETA_RSA_OAEP_H__ */
