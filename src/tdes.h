#ifndef __TDES_H__
#define __TDES_H__

typedef enum {
        DES_ENCRYPTION = 0,
        DES_DECRYPTION = 1,
} des_direction;

/* DES context */
typedef struct {
    des_direction dir;
    unsigned long long sk[16]; /* encryption/decryption subkeys */
} des_context;

/* Triple DES context */
typedef struct {
    des_direction dir;
    des_context des[3];
} des3_context;

int des_set_key(des_context *ctx, const unsigned char k[8], des_direction dir);

int des_exec(const des_context *ctx, const unsigned char input[8], unsigned char output[8]);

int des3_set_keys(des3_context *ctx, const unsigned char k1[8],  const unsigned char k2[8], const unsigned char k3[8], des_direction dir);

int des3_exec(const des3_context *ctx, const unsigned char input[8], unsigned char output[8]);

#endif /* __TDES_H__ */
