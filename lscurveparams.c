/*
 * gcc -o eckeycreate eckeycreate.c -lssl -lcrypto
 */

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <string.h>

int main() {

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  size_t num_curves = EC_get_builtin_curves(NULL, 0);
  /* EC_GROUP **curves = (EC_GROUP**)malloc(sizeof(EC_GROUP*)*num_curves); */
  EC_builtin_curve *builtin_curves = (EC_builtin_curve*)malloc(sizeof(EC_builtin_curve)*num_curves);
  (void)EC_get_builtin_curves(builtin_curves, num_curves);
  int i;
  for (i = 0; i < num_curves; ++i) {
    int error = 1;
    int nid = builtin_curves[i].nid;
    char *comment = builtin_curves[i].comment;

    // set up curve
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(nid);
    if (curve == NULL) {
      printf("Error getting curve ID: %d\n", nid);
      continue;
    }

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

    const char *sname;
    sname = OBJ_nid2sn(nid);
    if (sname == NULL)
      sname = "";
    printf("Name: %s\n",sname);
    printf("ID: %i\n",nid);
    const char *curve_name = EC_curve_nid2nist(nid);
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
    printf("Comment: %s\n",comment);

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
  free(builtin_curves);

  exit(0);
}
