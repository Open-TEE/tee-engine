/* crypto/rsa/rsa_oaep.c */
/* Written by Ulf Moeller. This software is distributed on an "AS IS"
   basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. */

/* EME-OAEP as defined in RFC 2437 (PKCS #1 v2.0) */

/* See Victor Shoup, "OAEP reconsidered," Nov. 2000,
 * <URL: http://www.shoup.net/papers/oaep.ps.Z>
 * for problems with the security proof for the
 * original OAEP scheme, which EME-OAEP is based on.
 *
 * A new proof can be found in E. Fujisaki, T. Okamoto,
 * D. Pointcheval, J. Stern, "RSA-OEAP is Still Alive!",
 * Dec. 2000, <URL: http://eprint.iacr.org/2000/061/>.
 * The new proof has stronger requirements for the
 * underlying permutation: "partial-one-wayness" instead
 * of one-wayness.  For the RSA function, this is
 * an equivalent notion.
 */

/*******************************************************************************
 * DISCLAIMER: Extracted from Openssl 1.0.2 beta version. This will be removed,
 * when stable version is containing neccessary functions or beta version
 * Heartbleed bug is fixed.
 *******************************************************************************/

#ifndef __OPENSSL_1_0_2_BETA_RSA_OAEP_H__
#define __OPENSSL_1_0_2_BETA_RSA_OAEP_H__

#include <openssl/evp.h>

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

#endif /* __OPENSSL_1_0_2_BETA_RSA_OAEP_H__ */
