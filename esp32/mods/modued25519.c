/*
 * Copyright (c) 2019, ubirch GmbH
 *
 * This software is licensed under the GNU GPL version 3 or any
 * later version, with permitted additional terms. For more information
 * see the Pycom Licence v1.0 document supplied with this file, or
 * available at https://www.pycom.io/opensource/licensing
 */

#include <assert.h>
#include <string.h>

#include "py/mpconfig.h"
#include "py/nlr.h"
#include "py/runtime.h"
#include "py/objstr.h"
#include "esp_system.h"
#include "hwcrypto/aes.h"
#include "hwcrypto/sha.h"
#include "mpexception.h"
#include "armnacl.h"

typedef struct _mp_obj_sk_t {
    mp_obj_base_t base;
    unsigned char *key[crypto_sign_SECRETKEYBYTES];
} mp_obj_sk_t;

typedef struct _mp_obj_vk_t {
    mp_obj_base_t base;
    unsigned char *key[crypto_sign_PUBLICKEYBYTES];
} mp_obj_vk_t;


/// \classmethod \constructor([key])
/// the key bytes must be passed
STATIC mp_obj_t key_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo;

    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    mp_obj_t self;

    switch (type->name) {
        case MP_QSTR_SigningKey: {
            self = m_new_obj(mp_obj_sk_t);
            memset(self, 0, sizeof(mp_obj_sk_t));
            if (bufinfo.len != crypto_sign_SECRETKEYBYTES) {
                mp_raise_ValueError("ed25519: signing key must be 64 bytes");
            }

            ((mp_obj_sk_t *) self)->base.type = type;
            memcpy(((mp_obj_sk_t *) self)->key, bufinfo.buf, bufinfo.len);
            break;
        }
        case MP_QSTR_VerifyingKey: {
            self = m_new_obj(mp_obj_vk_t);
            memset(self, 0, sizeof(mp_obj_vk_t));
            if (bufinfo.len != crypto_sign_PUBLICKEYBYTES) {
                mp_raise_ValueError("ed25519: signing key must be 32 bytes");
            }

            ((mp_obj_vk_t *) self)->base.type = type;
            memcpy(((mp_obj_vk_t *) self)->key, bufinfo.buf, bufinfo.len);
            break;
        }
        default:
            mp_raise_msg(&mp_type_OSError, "ed25519: unknown key type");
    }

    return self;
}

/***************************************************************************************
 * VerifyingKey
 */

STATIC mp_obj_t vk_verify(mp_obj_t self_in, mp_obj_t signature, mp_obj_t data) {
    mp_obj_vk_t *self = self_in;
    mp_buffer_info_t data_bufinfo, sig_bufinfo;
    crypto_uint16 smlen, mlen;

    mp_get_buffer_raise(data, &data_bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(signature, &sig_bufinfo, MP_BUFFER_READ);

    if (sig_bufinfo.len != crypto_sign_BYTES) {
        mp_raise_ValueError("ed25519: signature must be 64 bytes");
    }

    // prepare verification buffers
    smlen = (crypto_uint16) (crypto_sign_BYTES + data_bufinfo.len);

    unsigned char *sm = (unsigned char *) malloc(smlen);
    unsigned char *m = (unsigned char *) malloc(smlen);
    if (!m) {
        if (sm) free(sm);
        mp_raise_msg(&mp_type_OSError, "ed25519: out of memory");
    }

    // initialize signed message structure
    memcpy(sm, sig_bufinfo.buf, crypto_sign_BYTES);
    memcpy(sm + crypto_sign_BYTES, data_bufinfo.buf, data_bufinfo.len);

    // verify signature
    int ret = crypto_sign_open(m, &mlen, sm, smlen, (const unsigned char *) self->key);
    printf("ed25519: verify: %d\r\n", ret);

    free(m);
    // cppcheck-suppress doubleFree
    free(sm);

    if (ret) {
        mp_raise_ValueError("ed25519: signature verification failed");
    }

    return mp_obj_new_bool(!ret);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(vk_verify_obj, vk_verify);

STATIC mp_obj_t vk_to_bytes(mp_obj_t self_in) {
    mp_obj_vk_t *vk = self_in;
    return mp_obj_new_str_of_type(&mp_type_str, (const byte *) vk->key, crypto_sign_PUBLICKEYBYTES);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(vk_to_bytes_obj, vk_to_bytes);

STATIC const mp_map_elem_t vk_locals_dict_table[] = {
        {MP_OBJ_NEW_QSTR(MP_QSTR_verify),   (mp_obj_t) &vk_verify_obj},
        {MP_OBJ_NEW_QSTR(MP_QSTR_to_bytes), (mp_obj_t) &vk_to_bytes_obj},
};

STATIC MP_DEFINE_CONST_DICT(vk_locals_dict, vk_locals_dict_table);

STATIC const mp_obj_type_t verifying_key_type = {
        {&mp_type_type},
        .name = MP_QSTR_VerifyingKey,
        .make_new = key_make_new,
        .locals_dict = (mp_obj_t) &vk_locals_dict,
};

/***************************************************************************************
 * SigningKey
 */

STATIC mp_obj_t sk_sign(mp_obj_t self_in, mp_obj_t data) {
    mp_obj_sk_t *self = self_in;
    mp_buffer_info_t bufinfo;
    crypto_uint16 mlen;
    mp_obj_t signature;

    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    printf("ed25519: signing %d bytes\n", bufinfo.len);

    unsigned char *sm = (unsigned char *) malloc(crypto_sign_BYTES + bufinfo.len);
    if (!sm) {
        mp_raise_msg(&mp_type_OSError, "ed25519: out of memory");
    }

    // sign the message
    crypto_sign(sm, &mlen, bufinfo.buf, (crypto_uint16) bufinfo.len, (const unsigned char *) self->key);
    signature = mp_obj_new_bytes(sm, crypto_sign_BYTES);
    // free temporary buffer that contained signature and message
    free(sm);

    return signature;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(sk_sign_obj, sk_sign);

STATIC mp_obj_t sk_get_verifying_key(mp_obj_t self_in) {
    mp_obj_sk_t *sk = self_in;
    mp_obj_vk_t *vk;

    vk = m_new_obj(mp_obj_vk_t);
    vk->base.type = &verifying_key_type;
    memcpy(vk->key, sk->key + 32, crypto_sign_PUBLICKEYBYTES);

    return vk;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(sk_get_verifying_key_obj, sk_get_verifying_key);

STATIC mp_obj_t sk_to_bytes(mp_obj_t self_in) {
    mp_obj_sk_t *sk = self_in;
    return mp_obj_new_str_of_type(&mp_type_str, (const byte *) sk->key, crypto_sign_SECRETKEYBYTES);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(sk_to_bytes_obj, sk_to_bytes);

STATIC const mp_map_elem_t sk_locals_dict_table[] = {
        {MP_OBJ_NEW_QSTR(MP_QSTR_sign),              (mp_obj_t) &sk_sign_obj},
        {MP_OBJ_NEW_QSTR(MP_QSTR_get_verifying_key), (mp_obj_t) &sk_get_verifying_key_obj},
        {MP_OBJ_NEW_QSTR(MP_QSTR_to_bytes),          (mp_obj_t) &sk_to_bytes_obj},
};

STATIC MP_DEFINE_CONST_DICT(sk_locals_dict, sk_locals_dict_table);

STATIC const mp_obj_type_t signing_key_type = {
        {&mp_type_type},
        .name = MP_QSTR_SigningKey,
        .make_new = key_make_new,
        .locals_dict = (mp_obj_t) &sk_locals_dict,
};

/***************************************************************************************
 * ed25519 module
 */

STATIC mp_obj_t create_keypair(void) {
    mp_obj_t keys[2];
    mp_obj_vk_t *vk;
    mp_obj_sk_t *sk;

    vk = m_new_obj(mp_obj_vk_t);
    sk = m_new_obj(mp_obj_sk_t);
    vk->base.type = &verifying_key_type;
    sk->base.type = &signing_key_type;

    crypto_sign_keypair((unsigned char *) vk->key, (unsigned char *) sk->key);

    keys[0] = vk;
    keys[1] = sk;
    return mp_obj_new_tuple(2, keys);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_0(create_keypair_obj, create_keypair);

STATIC const mp_map_elem_t mp_module_ed25519_globals_table[] = {
        {MP_OBJ_NEW_QSTR(MP_QSTR___name__), MP_OBJ_NEW_QSTR(MP_QSTR_ed25519)},
        {MP_OBJ_NEW_QSTR(MP_QSTR_create_keypair), (mp_obj_t) &create_keypair_obj},
        {MP_OBJ_NEW_QSTR(MP_QSTR_SigningKey),     (mp_obj_t) &signing_key_type},
        {MP_OBJ_NEW_QSTR(MP_QSTR_VerifyingKey),   (mp_obj_t) &verifying_key_type},
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ed25519_globals, mp_module_ed25519_globals_table);

const mp_obj_module_t mp_module_ued25519 = {
        .base = {&mp_type_module},
        .globals = (mp_obj_dict_t *) &mp_module_ed25519_globals,
};
