/*
 * This file is derived from the MicroPython project, http://micropython.org/
 *
 * Copyright (c) 2018, Pycom Limited and its licensors.
 *
 * This software is licensed under the GNU GPL version 3 or any later version,
 * with permitted additional terms. For more information see the Pycom Licence
 * v1.0 document supplied with this file, or available at:
 * https://www.pycom.io/opensource/licensing
 */

/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013, 2014 Damien P. George
 * Copyright (c) 2015 Daniel Campora
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdint.h>
#include <string.h>

#include "py/mpconfig.h"
#include "py/obj.h"
#include "py/objstr.h"
#include "py/runtime.h"
#include "py/stream.h"
#include "py/mperrno.h"
#include "netutils.h"
#include "modnetwork.h"
#include "modwlan.h"
#include "modusocket.h"
#include "mpexception.h"

#include "esp_heap_caps.h"
#include "sdkconfig.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "nvs_flash.h"
#include "esp_event.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/******************************************************************************
 DEFINE PRIVATE CONSTANTS
 ******************************************************************************/
#define MODUSOCKET_MAX_SOCKETS                      15
#define MODUSOCKET_MAX_DNS_SERV                     2
/******************************************************************************
 DEFINE PRIVATE TYPES
 ******************************************************************************/
typedef struct {
    int32_t sd;
    bool    user;
} modusocket_sock_t;

/******************************************************************************
 DEFINE PRIVATE DATA
 ******************************************************************************/
STATIC const mp_obj_type_t socket_type;
STATIC const mp_obj_type_t raw_socket_type;
//STATIC OsiLockObj_t modusocket_LockObj;
STATIC modusocket_sock_t modusocket_sockets[MODUSOCKET_MAX_SOCKETS] = {{.sd = -1}, {.sd = -1}, {.sd = -1}, {.sd = -1}, {.sd = -1},
                                                                       {.sd = -1}, {.sd = -1}, {.sd = -1}, {.sd = -1}, {.sd = -1},
                                                                       {.sd = -1}, {.sd = -1}, {.sd = -1}, {.sd = -1}, {.sd = -1}};

/******************************************************************************
 DEFINE PUBLIC FUNCTIONS
 ******************************************************************************/
void modusocket_pre_init (void) {
    // create the wlan lock
//    ASSERT(OSI_OK == sl_LockObjCreate(&modusocket_LockObj, "SockLock"));
//    sl_LockObjUnlock (&modusocket_LockObj);
}

void modusocket_socket_add (int32_t sd, bool user) {
//    sl_LockObjLock (&modusocket_LockObj, SL_OS_WAIT_FOREVER);
    for (int i = 0; i < MODUSOCKET_MAX_SOCKETS; i++) {
        if (modusocket_sockets[i].sd < 0) {
            modusocket_sockets[i].sd = sd;
            modusocket_sockets[i].user = user;
            break;
        }
    }
//    sl_LockObjUnlock (&modusocket_LockObj);
}

void modusocket_check_numdns (mp_obj_t numdns) {
    //  Check if the index is not numeric
    if (!MP_OBJ_IS_SMALL_INT(numdns)) {
        nlr_raise(mp_obj_new_exception_msg(&mp_type_ValueError, mpexception_num_type_invalid_arguments));
    }
    //  Check if the index is numeric and exceeds MODUSOCKET_MAX_DNS_SERV (index starts at 0!)
    if (mp_obj_get_int(numdns) >= MODUSOCKET_MAX_DNS_SERV) {
        nlr_raise(mp_obj_new_exception_msg(&mp_type_ValueError, "Index out of range!\n"));
    }
}


void modusocket_socket_delete (int32_t sd) {
//    sl_LockObjLock (&modusocket_LockObj, SL_OS_WAIT_FOREVER);
    for (int i = 0; i < MODUSOCKET_MAX_SOCKETS; i++) {
        if (modusocket_sockets[i].sd == sd) {
            modusocket_sockets[i].sd = -1;
            break;
        }
    }
//    sl_LockObjUnlock (&modusocket_LockObj);
}

//void modusocket_enter_sleep (void) {
//    fd_set socketset;
//    int32_t maxfd = 0;
//
//    for (int i = 0; i < MOD_NETWORK_MAX_SOCKETS; i++) {
//        int32_t sd;
//        if ((sd = modusocket_sockets[i].u.sd) >= 0) {
//            FD_SET(sd, &socketset);
//            maxfd = (maxfd > sd) ? maxfd : sd;
//        }
//    }
//
//    if (maxfd > 0) {
//        // wait for any of the sockets to become ready...
//        sl_Select(maxfd + 1, &socketset, NULL, NULL, NULL);
//    }
//}

void modusocket_close_all_user_sockets (void) {
//    sl_LockObjLock (&modusocket_LockObj, SL_OS_WAIT_FOREVER);
    for (int i = 0; i < MODUSOCKET_MAX_SOCKETS; i++) {
        if (modusocket_sockets[i].sd >= 0 && modusocket_sockets[i].user) {
//            sl_Close(modusocket_sockets[i].u.sd); // FIXME
            modusocket_sockets[i].sd = -1;
        }
    }
//    sl_LockObjUnlock (&modusocket_LockObj);
}

///******************************************************************************/
// socket class

STATIC void socket_select_nic(mod_network_socket_obj_t *self, const byte *ip) {
    if (self->sock_base.nic == MP_OBJ_NULL) {
        // select a nic
        self->sock_base.nic = mod_network_find_nic(self, ip);
        self->sock_base.nic_type = (mod_network_nic_type_t*)mp_obj_get_type(self->sock_base.nic);
    }
}

// constructor socket(family=AF_INET, type=SOCK_STREAM, proto=IPPROTO_TCP, fileno=None)
STATIC mp_obj_t socket_make_new(const mp_obj_type_t *type, mp_uint_t n_args, mp_uint_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 4, false);

    // create socket object
    mod_network_socket_obj_t *s = m_new_obj_with_finaliser(mod_network_socket_obj_t);
    s->sock_base.nic_type = MP_OBJ_NULL;
    if (n_args > 0 &&
        (mp_obj_get_int(args[0]) == AF_LORA || mp_obj_get_int(args[0]) == AF_SIGFOX))
    {
        s->base.type = (mp_obj_t)&raw_socket_type;
        s->sock_base.u.u_param.type = SOCK_RAW;
    } else {
        s->base.type = (mp_obj_t)&socket_type;
        s->sock_base.u.u_param.domain = AF_INET;
        s->sock_base.u.u_param.type = SOCK_STREAM;
        s->sock_base.u.u_param.proto = IPPROTO_TCP;
    }
    s->sock_base.nic = MP_OBJ_NULL;
    s->sock_base.nic_type = NULL;
    s->sock_base.u.u_param.fileno = -1;
    s->sock_base.timeout = -1;      // sockets are blocking by default
    s->sock_base.is_ssl = false;
    s->sock_base.connected = false;

    if (n_args > 0) {
        s->sock_base.u.u_param.domain = mp_obj_get_int(args[0]);
        if (n_args > 1) {
            s->sock_base.u.u_param.type = mp_obj_get_int(args[1]);
            if (n_args > 2) {
                s->sock_base.u.u_param.proto = mp_obj_get_int(args[2]);
                if (n_args > 3) {
                    s->sock_base.u.u_param.fileno = mp_obj_get_int(args[3]);
                }
            }
        }
    }

    // don't forget to select a network card
    if (s->sock_base.u.u_param.domain == AF_INET) {
        socket_select_nic(s, (const byte *)"");
    } else {
        if (s->sock_base.u.u_param.type != SOCK_RAW) {
            nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, "incorrect socket type"));
        }
        socket_select_nic(s, NULL);
    }

    // now create the socket
    int _errno;
    if (s->sock_base.nic_type->n_socket(s, &_errno) != 0) {
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    // add the socket to the list
    modusocket_socket_add(s->sock_base.u.sd, true);

    return s;
}

STATIC mp_obj_t socket_fileno(mp_obj_t self_in) {
    mod_network_socket_obj_t *self = self_in;
    return MP_OBJ_NEW_SMALL_INT(self->sock_base.u.sd);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(socket_fileno_obj, socket_fileno);

// method socket.close()
STATIC mp_obj_t socket_close(mp_obj_t self_in) {
    mod_network_socket_obj_t *self = self_in;
    // this is to prevent the finalizer to close a socket that failed during creation
    if (self->sock_base.nic_type && self->sock_base.u.sd >= 0) {
        self->sock_base.nic_type->n_close(self);
        self->sock_base.u.sd = -1;
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(socket_close_obj, socket_close);

// method socket.bind(address)
STATIC mp_obj_t socket_bind(mp_obj_t self_in, mp_obj_t addr_in) {
    mod_network_socket_obj_t *self = self_in;
    int _errno;

#if defined (LOPY) || defined(LOPY4) || defined(FIPY)
    if (self->sock_base.nic_type == &mod_network_nic_type_lora) {
        mp_uint_t port = mp_obj_get_int(addr_in);

        if (self->sock_base.nic_type->n_bind(self, NULL, port, &_errno) != 0) {
            nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
        }
    } else {
#endif
        // get the address
        uint8_t ip[MOD_NETWORK_IPV4ADDR_BUF_SIZE];
        mp_uint_t port = netutils_parse_inet_addr(addr_in, ip, NETUTILS_LITTLE);

        if (self->sock_base.nic_type->n_bind(self, ip, port, &_errno) != 0) {
            nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
        }
#if defined (LOPY) || defined(LOPY4) || defined(FIPY)
    }
#endif
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(socket_bind_obj, socket_bind);

// method socket.listen([backlog])
STATIC mp_obj_t socket_listen(mp_uint_t n_args, const mp_obj_t *args) {
    mod_network_socket_obj_t *self = args[0];

    int32_t backlog = 0;
    if (n_args > 1) {
        backlog = mp_obj_get_int(args[1]);
        backlog = (backlog < 0) ? 0 : backlog;
    }

    int _errno;
    if (self->sock_base.nic_type->n_listen(self, backlog, &_errno) != 0) {
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(socket_listen_obj, 1, 2, socket_listen);

// method socket.accept()
STATIC mp_obj_t socket_accept(mp_obj_t self_in) {
    mod_network_socket_obj_t *self = self_in;

    // create new socket object
    mod_network_socket_obj_t *socket2 = m_new_obj_with_finaliser(mod_network_socket_obj_t);
    // the new socket inherits all properties from its parent
    memcpy (socket2, self, sizeof(mod_network_socket_obj_t));

    // accept the incoming connection
    uint8_t ip[MOD_NETWORK_IPV4ADDR_BUF_SIZE];
    mp_uint_t port;
    int _errno;
    MP_THREAD_GIL_EXIT();
    if (self->sock_base.nic_type->n_accept(self, socket2, ip, &port, &_errno) != 0) {
        MP_THREAD_GIL_ENTER();
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }

    MP_THREAD_GIL_ENTER();
    // add the socket to the list
    modusocket_socket_add(socket2->sock_base.u.sd, true);

    // make the return value
    mp_obj_tuple_t *client = mp_obj_new_tuple(2, NULL);
    client->items[0] = socket2;
    client->items[1] = netutils_format_inet_addr(ip, port, NETUTILS_LITTLE);
    return client;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(socket_accept_obj, socket_accept);

// method socket.connect(address)
STATIC mp_obj_t socket_connect(mp_obj_t self_in, mp_obj_t addr_in) {
    mod_network_socket_obj_t *self = self_in;

    // get address
    uint8_t ip[MOD_NETWORK_IPV4ADDR_BUF_SIZE];
    mp_uint_t port = netutils_parse_inet_addr(addr_in, ip, NETUTILS_LITTLE);

    // connect the socket
    int _errno;
    MP_THREAD_GIL_EXIT();
    if (self->sock_base.nic_type->n_connect(self, ip, port, &_errno) != 0) {
        MP_THREAD_GIL_ENTER();
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    MP_THREAD_GIL_ENTER();
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(socket_connect_obj, socket_connect);

// method socket.send(bytes)
STATIC mp_obj_t socket_send(mp_obj_t self_in, mp_obj_t buf_in) {
    mod_network_socket_obj_t *self = self_in;
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(buf_in, &bufinfo, MP_BUFFER_READ);
    int _errno;
    MP_THREAD_GIL_EXIT();
    mp_int_t ret = self->sock_base.nic_type->n_send(self, bufinfo.buf, bufinfo.len, &_errno);
    MP_THREAD_GIL_ENTER();
    if (ret < 0) {
        if (_errno == MP_EAGAIN && self->sock_base.timeout > 0) {
            nlr_raise(mp_obj_new_exception_msg(&mp_type_TimeoutError, "timed out"));
        }
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    return mp_obj_new_int_from_uint(ret);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(socket_send_obj, socket_send);

// method socket.recv(bufsize)
STATIC mp_obj_t socket_recv(mp_obj_t self_in, mp_obj_t len_in) {
    mod_network_socket_obj_t *self = self_in;
    mp_int_t len = mp_obj_get_int(len_in);
    vstr_t vstr;
    vstr_init_len(&vstr, len);
    int _errno;
    MP_THREAD_GIL_EXIT();
    mp_int_t ret = self->sock_base.nic_type->n_recv(self, (byte*)vstr.buf, len, &_errno);
    MP_THREAD_GIL_ENTER();
    if (ret < 0) {
        if (_errno == MP_EAGAIN) {
            if (self->sock_base.timeout > 0) {
                nlr_raise(mp_obj_new_exception_msg(&mp_type_TimeoutError, "timed out"));
            } else {
                ret = 0;        // non-blocking socket
            }
        } else {
            nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
        }
    }
    if (ret == 0) {
        return mp_const_empty_bytes;
    }
    vstr.len = ret;
    vstr.buf[vstr.len] = '\0';
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(socket_recv_obj, socket_recv);

// method socket.sendto(bytes, address)
STATIC mp_obj_t socket_sendto(mp_obj_t self_in, mp_obj_t data_in, mp_obj_t addr_in) {
    mod_network_socket_obj_t *self = self_in;

    // get the data
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data_in, &bufinfo, MP_BUFFER_READ);

    // get address
    uint8_t ip[MOD_NETWORK_IPV4ADDR_BUF_SIZE];
    mp_uint_t port = netutils_parse_inet_addr(addr_in, ip, NETUTILS_LITTLE);

    // call the nic to sendto
    int _errno;
    MP_THREAD_GIL_EXIT();
    mp_int_t ret = self->sock_base.nic_type->n_sendto(self, bufinfo.buf, bufinfo.len, ip, port, &_errno);
    MP_THREAD_GIL_ENTER();
    if (ret < 0) {
        if (_errno == MP_EAGAIN && self->sock_base.timeout > 0) {
            nlr_raise(mp_obj_new_exception_msg(&mp_type_TimeoutError, "timed out"));
        }
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    return mp_obj_new_int(ret);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(socket_sendto_obj, socket_sendto);

// method socket.recvfrom(bufsize)
STATIC mp_obj_t socket_recvfrom(mp_obj_t self_in, mp_obj_t len_in) {
    mod_network_socket_obj_t *self = self_in;
    vstr_t vstr;
    vstr_init_len(&vstr, mp_obj_get_int(len_in));
    byte ip[4];
    mp_uint_t port;
    int _errno;
    MP_THREAD_GIL_EXIT();
    mp_int_t ret = self->sock_base.nic_type->n_recvfrom(self, (byte*)vstr.buf, vstr.len, ip, &port, &_errno);
    MP_THREAD_GIL_ENTER();
    if (ret < 0) {
        if (_errno == MP_EAGAIN && self->sock_base.timeout > 0) {
            nlr_raise(mp_obj_new_exception_msg(&mp_type_TimeoutError, "timed out"));
        }
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    mp_obj_t tuple[2];
    if (ret == 0) {
        tuple[0] = mp_const_empty_bytes;
    } else {
        vstr.len = ret;
        vstr.buf[vstr.len] = '\0';
        tuple[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
    }
#if defined (LOPY) || defined(LOPY4) || defined(FIPY)
    if (self->sock_base.nic_type == &mod_network_nic_type_lora) {
        tuple[1] = mp_obj_new_int(port);
    } else {
        tuple[1] = netutils_format_inet_addr(ip, port, NETUTILS_LITTLE);
    }
#else
    tuple[1] = netutils_format_inet_addr(ip, port, NETUTILS_LITTLE);
#endif
    return mp_obj_new_tuple(2, tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(socket_recvfrom_obj, socket_recvfrom);

// method socket.setsockopt(level, optname, value)
STATIC mp_obj_t socket_setsockopt(mp_uint_t n_args, const mp_obj_t *args) {
    mod_network_socket_obj_t *self = args[0];

    mp_int_t level = mp_obj_get_int(args[1]);
    mp_int_t opt = mp_obj_get_int(args[2]);

    const void *optval;
    mp_uint_t optlen;
    mp_int_t val;
    if (mp_obj_is_integer(args[3])) {
        val = mp_obj_get_int_truncated(args[3]);
        optval = &val;
        optlen = sizeof(val);
    } else if (MP_OBJ_IS_TYPE(args[3], &mp_type_bool)) {
        val = mp_obj_is_true(args[3]);
        optval = &val;
        optlen = sizeof(val);
    } else {
        mp_buffer_info_t bufinfo;
        mp_get_buffer_raise(args[3], &bufinfo, MP_BUFFER_READ);
        optval = bufinfo.buf;
        optlen = bufinfo.len;
    }

    int _errno;
    if (self->sock_base.nic_type->n_setsockopt(self, level, opt, optval, optlen, &_errno) != 0) {
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(socket_setsockopt_obj, 4, 4, socket_setsockopt);

// method socket.settimeout(value)
// timeout=0 means non-blocking
// timeout=None means blocking
// otherwise, timeout is in seconds
STATIC mp_obj_t socket_settimeout(mp_obj_t self_in, mp_obj_t timeout_in) {
    mod_network_socket_obj_t *self = self_in;
    int32_t timeout;
    if (timeout_in == mp_const_none) {
        timeout = -1;
    } else {
        timeout = 1000 * mp_obj_get_float(timeout_in);
    }
    int _errno;
    if (self->sock_base.nic_type->n_settimeout(self, timeout, &_errno) != 0) {
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(socket_settimeout_obj, socket_settimeout);

// method socket.setblocking(flag)
STATIC mp_obj_t socket_setblocking(mp_obj_t self_in, mp_obj_t blocking) {
    if (mp_obj_is_true(blocking)) {
        return socket_settimeout(self_in, mp_const_none);
    } else {
        return socket_settimeout(self_in, MP_OBJ_NEW_SMALL_INT(0));
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(socket_setblocking_obj, socket_setblocking);

STATIC mp_obj_t socket_makefile(mp_uint_t n_args, const mp_obj_t *args) {
    // TODO: CPython explicitly says that closing the returned object doesn't
    // close the original socket (Python2 at all says that fd is dup()ed). But
    // we save on the bloat.
    mod_network_socket_obj_t *self = args[0];
    if (n_args > 1) {
        const char *mode = mp_obj_str_get_str(args[1]);
        if (strcmp(mode, "rb") && strcmp(mode, "wb")) {
            nlr_raise(mp_obj_new_exception_msg(&mp_type_ValueError, mpexception_value_invalid_arguments));
        }
    }
    return self;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(socket_makefile_obj, 1, 6, socket_makefile);

STATIC mp_obj_t socket_do_handshake(mp_obj_t self_in) {
    mod_network_socket_obj_t *self = self_in;

    int _errno;
    MP_THREAD_GIL_EXIT();
    if (self->sock_base.nic_type->n_setupssl(self, &_errno) != 0) {
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(_errno)));
    }
    MP_THREAD_GIL_ENTER();
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(socket_do_handshake_obj, socket_do_handshake);
STATIC const mp_map_elem_t socket_locals_dict_table[] = {
    { MP_OBJ_NEW_QSTR(MP_QSTR___del__),         (mp_obj_t)&socket_close_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_close),           (mp_obj_t)&socket_close_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_bind),            (mp_obj_t)&socket_bind_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_listen),          (mp_obj_t)&socket_listen_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_accept),          (mp_obj_t)&socket_accept_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_connect),         (mp_obj_t)&socket_connect_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_send),            (mp_obj_t)&socket_send_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_sendall),         (mp_obj_t)&socket_send_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_recv),            (mp_obj_t)&socket_recv_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_sendto),          (mp_obj_t)&socket_sendto_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_recvfrom),        (mp_obj_t)&socket_recvfrom_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_setsockopt),      (mp_obj_t)&socket_setsockopt_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_settimeout),      (mp_obj_t)&socket_settimeout_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_setblocking),     (mp_obj_t)&socket_setblocking_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_makefile),        (mp_obj_t)&socket_makefile_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_fileno),          (mp_obj_t)&socket_fileno_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_do_handshake),    (mp_obj_t)&socket_do_handshake_obj },

    // stream methods
    { MP_OBJ_NEW_QSTR(MP_QSTR_read),            (mp_obj_t)&mp_stream_read_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_readall),         (mp_obj_t)&mp_stream_readall_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_readinto),        (mp_obj_t)&mp_stream_readinto_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_readline),        (mp_obj_t)&mp_stream_unbuffered_readline_obj},
    { MP_OBJ_NEW_QSTR(MP_QSTR_write),           (mp_obj_t)&mp_stream_write_obj },
};

MP_DEFINE_CONST_DICT(socket_locals_dict, socket_locals_dict_table);

#if defined (LOPY) || defined(LOPY4) || defined (FIPY)
STATIC const mp_map_elem_t raw_socket_locals_dict_table[] = {
    { MP_OBJ_NEW_QSTR(MP_QSTR___del__),         (mp_obj_t)&socket_close_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_close),           (mp_obj_t)&socket_close_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_send),            (mp_obj_t)&socket_send_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_recv),            (mp_obj_t)&socket_recv_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_recvfrom),        (mp_obj_t)&socket_recvfrom_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_settimeout),      (mp_obj_t)&socket_settimeout_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_bind),            (mp_obj_t)&socket_bind_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_setblocking),     (mp_obj_t)&socket_setblocking_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_setsockopt),      (mp_obj_t)&socket_setsockopt_obj },
};
#else   // SIPY
STATIC const mp_map_elem_t raw_socket_locals_dict_table[] = {
    { MP_OBJ_NEW_QSTR(MP_QSTR___del__),         (mp_obj_t)&socket_close_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_close),           (mp_obj_t)&socket_close_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_send),            (mp_obj_t)&socket_send_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_recv),            (mp_obj_t)&socket_recv_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_settimeout),      (mp_obj_t)&socket_settimeout_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_setblocking),     (mp_obj_t)&socket_setblocking_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_setsockopt),      (mp_obj_t)&socket_setsockopt_obj },
};
#endif

MP_DEFINE_CONST_DICT(raw_socket_locals_dict, raw_socket_locals_dict_table);

STATIC mp_uint_t socket_read(mp_obj_t self_in, void *buf, mp_uint_t size, int *errcode) {
    mod_network_socket_obj_t *self = self_in;
    MP_THREAD_GIL_EXIT();
    mp_int_t ret = self->sock_base.nic_type->n_recv(self, buf, size, errcode);
    MP_THREAD_GIL_ENTER();
    if (ret < 0) {
//        // we need to ignore the socket closed error here because a readall() or read() without params
//        // only returns when the socket is closed by the other end
//        if (*errcode != ESECCLOSED) {
            ret = MP_STREAM_ERROR;
//        } else {
//            ret = 0;  // TODO: Do we need a similar check here for lwip?
//        }
    }
    return ret;
}

STATIC mp_uint_t socket_write(mp_obj_t self_in, const void *buf, mp_uint_t size, int *errcode) {
    mod_network_socket_obj_t *self = self_in;
    MP_THREAD_GIL_EXIT();
    mp_int_t ret = self->sock_base.nic_type->n_send(self, buf, size, errcode);
    MP_THREAD_GIL_ENTER();
    if (ret < 0) {
        ret = MP_STREAM_ERROR;
    }
    return ret;
}

STATIC mp_uint_t socket_ioctl(mp_obj_t self_in, mp_uint_t request, mp_uint_t arg, int *errcode) {
    mod_network_socket_obj_t *self = self_in;
    return self->sock_base.nic_type->n_ioctl(self, request, arg, errcode);
}

const mp_stream_p_t socket_stream_p = {
    .read = socket_read,
    .write = socket_write,
    .ioctl = socket_ioctl,
    .is_text = false,
};

const mp_stream_p_t raw_socket_stream_p = {
    .ioctl = socket_ioctl,
    .is_text = false,
};

STATIC const mp_obj_type_t socket_type = {
    { &mp_type_type },
    .name = MP_QSTR_socket,
    .make_new = socket_make_new,
    .protocol = &socket_stream_p,
    .locals_dict = (mp_obj_t)&socket_locals_dict,
};

STATIC const mp_obj_type_t raw_socket_type = {
    { &mp_type_type },
    .name = MP_QSTR_socket,
    .make_new = socket_make_new,
    .protocol = &raw_socket_stream_p,
    .locals_dict = (mp_obj_t)&raw_socket_locals_dict,
};

///******************************************************************************/
//// usocket module

// function usocket.getaddrinfo(host, port)
/// \function getaddrinfo(host, port)
STATIC mp_obj_t mod_usocket_getaddrinfo(mp_obj_t host_in, mp_obj_t port_in) {
    mp_uint_t hlen;
    const char *host = mp_obj_str_get_data(host_in, &hlen);
    mp_int_t port = mp_obj_get_int(port_in);
    bool is_inf_down = false;

    // find a nic that can do a name lookup
    for (mp_uint_t i = 0; i < MP_STATE_PORT(mod_network_nic_list).len; i++) {
        mp_obj_t nic = MP_STATE_PORT(mod_network_nic_list).items[i];
        mod_network_nic_type_t *nic_type = (mod_network_nic_type_t*)mp_obj_get_type(nic);
        if (nic_type->n_gethostbyname != NULL && nic_type->inf_up != NULL)
        {
			if (nic_type->inf_up()) {

				is_inf_down = false;
				// ipv4 only
				uint8_t out_ip[MOD_NETWORK_IPV4ADDR_BUF_SIZE];
				int32_t result = nic_type->n_gethostbyname(host, hlen, out_ip, AF_INET);
				if (result < 0) {
					// negate result as it contains the error code which must be positive
					nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(result)));
				}
				mp_obj_tuple_t *tuple = mp_obj_new_tuple(5, NULL);
				tuple->items[0] = MP_OBJ_NEW_SMALL_INT(AF_INET);
				tuple->items[1] = MP_OBJ_NEW_SMALL_INT(SOCK_STREAM);
				tuple->items[2] = MP_OBJ_NEW_SMALL_INT(0);
				tuple->items[3] = MP_OBJ_NEW_QSTR(MP_QSTR_);
				tuple->items[4] = netutils_format_inet_addr(out_ip, port, NETUTILS_BIG);
				return mp_obj_new_list(1, (mp_obj_t*)&tuple);
			}
			else
			{
				is_inf_down = true;
				continue;
			}
        }
    }
    if(is_inf_down)
    {
    	nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, "Avialable Interfaces are down"));
    }
    else
    {
    	nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, "no available NIC"));
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_usocket_getaddrinfo_obj, mod_usocket_getaddrinfo);

STATIC mp_obj_t mod_usocket_dnsserver(size_t n_args, const mp_obj_t *args)
{
    if(n_args == 1)
    {
        mp_obj_t tuple[2];
        ip_addr_t ipaddr;
        modusocket_check_numdns(args[0]);
        uint8_t numdns = mp_obj_get_int(args[0]);

        ipaddr = dns_getserver(numdns);
        if(ipaddr.type == 0)
        {
            tuple[0] = mp_obj_new_int(numdns);
            tuple[1] = netutils_format_ipv4_addr((uint8_t *)&ipaddr.u_addr.ip4.addr, NETUTILS_BIG);
        }
        else
        {
            nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, "Only IPv4 addresses are currently supported\n"));
        }
        return mp_obj_new_tuple(2, tuple);
    }
    else if(n_args > 1)
    {
        ip_addr_t dnsserver;
        modusocket_check_numdns(args[0]);
        uint8_t numdns = mp_obj_get_int(args[0]);
        //parse dns Server IP
        netutils_parse_ipv4_addr(args[1], (uint8_t *)&dnsserver.u_addr.ip4.addr, NETUTILS_BIG);
        //IPv4
        dnsserver.type = 0;

        //set DNS Server
        dns_setserver(numdns, &dnsserver);

        return mp_const_none;

    }
    else
    {
        mp_obj_t tuple[MODUSOCKET_MAX_DNS_SERV];
        for(int i=0; i < MODUSOCKET_MAX_DNS_SERV; i++) {
            ip_addr_t ipaddr = dns_getserver(i);
            tuple[i] = netutils_format_ipv4_addr((uint8_t *)&ipaddr.u_addr.ip4.addr, NETUTILS_BIG);
        }
        return mp_obj_new_tuple(MODUSOCKET_MAX_DNS_SERV, tuple);
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_usocket_dnsserver_obj, 0, 2, mod_usocket_dnsserver);

STATIC const mp_map_elem_t mp_module_usocket_globals_table[] = {
    { MP_OBJ_NEW_QSTR(MP_QSTR___name__),        MP_OBJ_NEW_QSTR(MP_QSTR_usocket) },

    { MP_OBJ_NEW_QSTR(MP_QSTR_socket),          (mp_obj_t)&socket_type },
    { MP_OBJ_NEW_QSTR(MP_QSTR_getaddrinfo),     (mp_obj_t)&mod_usocket_getaddrinfo_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_dnsserver),       (mp_obj_t)&mod_usocket_dnsserver_obj },

    // class exceptions
    { MP_OBJ_NEW_QSTR(MP_QSTR_error),           (mp_obj_t)&mp_type_OSError },
    { MP_OBJ_NEW_QSTR(MP_QSTR_timeout),         (mp_obj_t)&mp_type_TimeoutError },

    // class constants
    { MP_OBJ_NEW_QSTR(MP_QSTR_AF_INET),         MP_OBJ_NEW_SMALL_INT(AF_INET) },
#if defined (LOPY) || defined (LOPY4) || defined (FIPY)
    { MP_OBJ_NEW_QSTR(MP_QSTR_AF_LORA),         MP_OBJ_NEW_SMALL_INT(AF_LORA) },
#endif

#if defined (SIPY) || defined (LOPY4) || defined (FIPY)
    { MP_OBJ_NEW_QSTR(MP_QSTR_AF_SIGFOX),       MP_OBJ_NEW_SMALL_INT(AF_SIGFOX) },
#endif

    { MP_OBJ_NEW_QSTR(MP_QSTR_SOCK_STREAM),     MP_OBJ_NEW_SMALL_INT(SOCK_STREAM) },
    { MP_OBJ_NEW_QSTR(MP_QSTR_SOCK_DGRAM),      MP_OBJ_NEW_SMALL_INT(SOCK_DGRAM) },
#if defined (LOPY) || defined (SIPY) || defined (LOPY4) || defined(FIPY)
    { MP_OBJ_NEW_QSTR(MP_QSTR_SOCK_RAW),        MP_OBJ_NEW_SMALL_INT(SOCK_RAW) },
#endif

    { MP_OBJ_NEW_QSTR(MP_QSTR_IPPROTO_TCP),     MP_OBJ_NEW_SMALL_INT(IPPROTO_TCP) },
    { MP_OBJ_NEW_QSTR(MP_QSTR_IPPROTO_UDP),     MP_OBJ_NEW_SMALL_INT(IPPROTO_UDP) },
#if defined(LOPY)
    { MP_OBJ_NEW_QSTR(MP_QSTR_SOL_LORA),        MP_OBJ_NEW_SMALL_INT(SOL_LORA) },
#elif defined(SIPY)
    { MP_OBJ_NEW_QSTR(MP_QSTR_SOL_SIGFOX),      MP_OBJ_NEW_SMALL_INT(SOL_SIGFOX) },
#elif defined(FIPY) || defined(LOPY4)
    { MP_OBJ_NEW_QSTR(MP_QSTR_SOL_LORA),        MP_OBJ_NEW_SMALL_INT(SOL_LORA) },
    { MP_OBJ_NEW_QSTR(MP_QSTR_SOL_SIGFOX),      MP_OBJ_NEW_SMALL_INT(SOL_SIGFOX) },
#endif
    { MP_OBJ_NEW_QSTR(MP_QSTR_SOL_SOCKET),      MP_OBJ_NEW_SMALL_INT(SOL_SOCKET) },
    { MP_OBJ_NEW_QSTR(MP_QSTR_SO_REUSEADDR),    MP_OBJ_NEW_SMALL_INT(SO_REUSEADDR) },

#if defined(LOPY) || defined (LOPY4) || defined(FIPY)
    { MP_OBJ_NEW_QSTR(MP_QSTR_SO_CONFIRMED),    MP_OBJ_NEW_SMALL_INT(SO_LORAWAN_CONFIRMED) },
    { MP_OBJ_NEW_QSTR(MP_QSTR_SO_DR),           MP_OBJ_NEW_SMALL_INT(SO_LORAWAN_DR) },
#endif
#if defined(SIPY) || defined (LOPY4) || defined(FIPY)
     { MP_OBJ_NEW_QSTR(MP_QSTR_SO_RX),          MP_OBJ_NEW_SMALL_INT(SO_SIGFOX_RX) },
     { MP_OBJ_NEW_QSTR(MP_QSTR_SO_TX_REPEAT),   MP_OBJ_NEW_SMALL_INT(SO_SIGFOX_TX_REPEAT) },
     { MP_OBJ_NEW_QSTR(MP_QSTR_SO_OOB),         MP_OBJ_NEW_SMALL_INT(SO_SIGFOX_OOB) },
     { MP_OBJ_NEW_QSTR(MP_QSTR_SO_BIT),         MP_OBJ_NEW_SMALL_INT(SO_SIGFOX_BIT) },
#endif
};

STATIC MP_DEFINE_CONST_DICT(mp_module_usocket_globals, mp_module_usocket_globals_table);

const mp_obj_module_t mp_module_usocket = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_usocket_globals,
};
