/*
 * gcc -o hasecc hasecc.c -lssl -lcrypto
 * USAGE:
 *
 */

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <string.h>

int main(int argc, char **argv) {

  // initialize openssl
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  // Get list of curves from args but don't use program name
  const int numcurves = argc - 1;
  char **curvenames = &(argv[1]);

  printf("Curves: ");
  for (int i = 0; i < numcurves; ++i) {
    printf("%s ", curvenames[i]);
  }
  printf("\n");

  // set up curves
  EC_GROUP **curves = (EC_GROUP**)malloc(sizeof(EC_GROUP*)*numcurves);
  for (int i = 0; i < numcurves; ++i) {
    int curve_nid = OBJ_txt2nid(curvenames[i]);

    // Get curve by nid
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(curve_nid);
    if (curve == NULL) {
      printf("Error getting curve %s, ID: %d\n", curvenames[i], curve_nid);
      continue;
    }

    // put curve in our array
    curves[i] = curve;
  }

  // print off info for each curve specified
  printf("--------------------------------------------------------------------------------\n");
  for (int i = 0; i < numcurves; ++i) {
    int error = 1;

    EC_GROUP *curve = curves[i];
    
    // parameters
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *cofactor = BN_new();
    BIGNUM *order = BN_new();

    EC_POINT *generator = EC_POINT_new(curve);
    BIGNUM *gen_x = BN_new();
    BIGNUM *gen_y = BN_new();

    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BN_CTX *c_ctx = BN_CTX_new();

    error = EC_GROUP_get_cofactor(curve, cofactor, ctx);
    if (error == 0) {
      printf("Error getting cofactor\n");
      continue;
    }
    char *cofactor_str = BN_bn2dec(cofactor);

    /* EC_METHOD *method = EC_GROUP_method_of(curve); */
    /* if (method == NULL) { */
    /*   printf("Error getting method\n"); */
    /*   continue; */
    /* } */

    error = EC_GROUP_get_order(curve, order, ctx);
    if (error == 0) {
      printf("Error getting order\n");
      continue;
    }
    char *order_str = BN_bn2dec(order);

    // Have to have generated a key to have a generator, but here's the code
    // https://stackoverflow.com/questions/18496436/openssl-print-x-and-y-of-ec-point
    /* generator = EC_GROUP_get0_generator(curve); */

    error = EC_GROUP_get_curve_GFp(curve, p, a, b, c_ctx);
    if (error == 0) {
      printf("Error getting p, a and b\n");
      continue;
    }
    char *p_str = BN_bn2dec(p);
    char *a_str = BN_bn2dec(a);
    char *b_str = BN_bn2dec(b);

    BN_CTX *d_ctx = BN_CTX_new();
    int discrim = EC_GROUP_check_discriminant(curve, d_ctx);
    // TODO: Calculate real discriminant (-16(4a^3+27b^2))
    // (-64*(a^3)-432*(b^2)))
    /* BIGNUM *d = BN_new(); */
    /* BIGNUM *a_cubed = BN_new(); */
    /* BIGNUM *three = BN_new(); */
    /* BN_dec2bn(three, "0"); */
    /* int BN_exp(a_cubed, BIGNUM *a, BIGNUM *p, BN_CTX *ctx); */
    /* int BN_add(BIGNUM *d, const BIGNUM *a, const BIGNUM *b); */
    /* int BN_sub(BIGNUM *d, const BIGNUM *a, const BIGNUM *b); */
    /* int BN_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx); */
    /* int BN_sqr(BIGNUM *r, BIGNUM *a, BN_CTX *ctx); */
    /* int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, */
    /*            BN_CTX *ctx); */


    const char *curve_name = curvenames[i];
    if (curve_name != NULL) {
      printf("NIST Name: %s\n", curve_name);
    }
    printf("Cofactor: %s\n",cofactor_str);
    printf("Order: %s\n",order_str);
    printf("Degree: %d\n", EC_GROUP_get_degree(curve));
    printf("p: %s\n",p_str);
    printf("a: %s\n",a_str);
    printf("b: %s\n",b_str);
    if (discrim) {
      printf("Discriminant != 0\n");
    } else {
      printf("Discriminant == 0\n");
    }
    printf("--------------------------------------------------------------------------------\n");

    // free everything
    BN_CTX_free(ctx);
    BN_CTX_free(c_ctx);
    BN_CTX_free(d_ctx);
    BN_free(cofactor);
    BN_free(order);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(gen_x);
    BN_free(gen_y);
    EC_GROUP_free(curve);
    EC_POINT_free(generator);
  }

  return 0;
}
