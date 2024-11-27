#ifndef _PKT_DCOM_H_
#define _PKT_DCOM_H_

#include <ngx_core.h>
#include <nginx.h>
#include <stdbool.h>

// Specific OBJREF
#define OBJREF_FLAGS_STANDARD   0x1
#define OBJREF_FLAGS_HANDLER    0x2
#define OBJREF_FLAGS_CUSTOM     0x4
// #define OBJREF_FLAGS_EXTENDED   0x8

// the first 4 bytes of GUID
#define UUID_ISYS_ACTIVATOR         0x000001a0
#define IID_ACTI_PROPS_IN           0x000001a2
#define IID_ACTI_PROPS_OUT          0x000001a3
#define CLSID_SPEC_SYS_PROPS        0x000001b9
#define CLSID_INSTANTIATE_INFO      0x000001ab
#define CLSID_ACTIVATE_INFO         0x000001a5
#define CLSID_CTX_MARSHALER         0x0000033b
#define CLSID_SECURITY_INFO         0x000001a6
#define CLSID_SRV_LOCATION          0x000001a4
#define CLSID_SCM_REQUEST           0x000001aa
#define CLSID_PROPS_OUT             0x00000339
#define CLSID_SCM_REPLY             0x000001b6

// Simple type dissectors
ngx_int_t
dissect_ndr_uint8(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint8_t *pdata);
ngx_int_t
dissect_ndr_uint16(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint16_t *pdata);
ngx_int_t
dissect_ndr_uint32(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata);
ngx_int_t
dissect_ndr_duint32(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint64_t *pdata);
ngx_int_t
dissect_ndr_uint64(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint64_t *pdata);
ngx_int_t
dissect_ndr_float(ngx_buf_t *buffer, ngx_int_t offset, bool endian, float *pdata);
ngx_int_t
dissect_ndr_double(ngx_buf_t *buffer, ngx_int_t offset, bool endian, double *pdata);

#define dissect_dcom_FILETIME       dissect_ndr_duint32
#define dissect_dcom_BOOLEAN        dissect_ndr_uint8
#define dissect_dcom_BYTE           dissect_ndr_uint8
#define dissect_dcom_VARIANT_BOOL   dissect_ndr_uint16
#define dissect_dcom_WORD           dissect_ndr_uint16
#define dissect_dcom_DWORD          dissect_ndr_uint32
#define dissect_dcom_ID             dissect_ndr_duint32
#define dissect_dcom_I8             dissect_ndr_uint64
#define dissect_dcom_FLOAT          dissect_ndr_float
#define dissect_dcom_DOUBLE         dissect_ndr_double
#define dissect_dcom_DATE           dissect_ndr_double

// DCOM Response Type
typedef enum {
    DCOM_RESP_UNKNOWN,
    DCOM_RESP_SERVER_ALIVE2,
    DCOM_RESP_RESOLVE_OXID2,
    DCOM_RESP_CREATE_INSTANCE
} dcom_resp_t;

// Filter DCOM data type
typedef struct {
    u_char iip[64];   // ip in
    uint16_t iport;   // port in
    u_char oip[64];   // ip out
    uint16_t oport;   // port out
} filter_dcom_data_t;

#if 0
// DCOM varieble type
typedef enum {
    DCOM_VT_EMPTY           = 0,
    DCOM_VT_NULL            = 1,
    DCOM_VT_I2              = 2,
    DCOM_VT_I4              = 3,
    DCOM_VT_R4              = 4,
    DCOM_VT_R8              = 5,
    DCOM_VT_CY              = 6,
    DCOM_VT_DATE            = 7,
    DCOM_VT_BSTR            = 8,
    DCOM_VT_DISPATCH        = 9,
    DCOM_VT_ERROR           = 10,
    DCOM_VT_BOOL            = 11,
    DCOM_VT_VARIANT         = 12,
    DCOM_VT_UNKNOWN         = 13,
    DCOM_VT_DECIMAL         = 14,
    DCOM_VT_I1              = 16,
    DCOM_VT_UI1             = 17,
    DCOM_VT_UI2             = 18,
    DCOM_VT_UI4             = 19,
    DCOM_VT_I8              = 20,
    DCOM_VT_UI8             = 21,
    DCOM_VT_INT             = 22,
    DCOM_VT_UINT            = 23,
    DCOM_VT_VOID            = 24,
    DCOM_VT_HRESULT         = 25,
    DCOM_VT_PTR             = 26,
    DCOM_VT_SAFEARRAY       = 27,
    DCOM_VT_CARRAY          = 28,
    DCOM_VT_USERDEFINED     = 29,
    DCOM_VT_LPSTR           = 30,
    DCOM_VT_LPWSTR          = 31,
    DCOM_VT_RECORD          = 36,
    DCOM_VT_FILETIME        = 64,
    DCOM_VT_BLOB            = 65,
    DCOM_VT_STREAM          = 66,
    DCOM_VT_STORAGE         = 67,
    DCOM_VT_STREAMED_OBJECT = 68,
    DCOM_VT_STORED_OBJECT   = 69,
    DCOM_VT_BLOB_OBJECT     = 70,
    DCOM_VT_CF              = 71,
    DCOM_VT_CLSID           = 72,
    DCOM_VT_BSTR_BLOB       = 0x0fff,
    DCOM_VT_VECTOR          = 0x1000,
    DCOM_VT_ARRAY           = 0x2000,
    DCOM_VT_BYREF           = 0x4000,
    DCOM_VT_RESERVED        = 0x8000,
    DCOM_VT_ILLEGAL         = 0xffff,
    DCOM_VT_ILLEGALMASKED   = 0x0fff,
    DCOM_VT_TYPEMASK        = 0x0fff
} dcom_vartype_t;
#endif

#define DCE_COMMON_HDR_SIZE   16
#define DCE_RESP_SPEC_HDR_SIZE 8

#pragma pack(push, 1)

// DCE/RPC common header
typedef struct {
    uint8_t rpc_ver;
    uint8_t rpc_ver_minor;
    uint8_t ptype;
    uint8_t flags;
    uint8_t drep[4];
    uint16_t frag_len;
    uint16_t auth_len;
    uint32_t call_id;
} dce_common_hdr_t;

// response PDU specific header
typedef struct {
    uint32_t alloc_hint;
    uint16_t ctx_id;
    uint8_t cancel_cnt;
    uint8_t reserved;
} dce_resp_spec_hdr_t;

#pragma pack(pop)

// Definition of machine/object/guid/interface
typedef struct {
    void *objects;  // object list
    ngx_int_t first_packet;
    unsigned int ip[4];
} dcom_machine_t;

typedef struct {
    dcom_machine_t *parent;
    void *interfaces;
    void *private_data;
    ngx_int_t first_packet;
    uint64_t oid;
    uint64_t oxid;
} dcom_object_t;

typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} e_guid_t;

typedef struct {
    dcom_object_t *parent;
    void *private_data;
    ngx_int_t first_packet;
    e_guid_t iid;
    e_guid_t ipid;
} dcom_interface_t;

typedef ngx_int_t (*dcom_dissect_fn_t) (ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t size);

typedef struct {
    void *parent;
    void *private_data;
    e_guid_t *uuid;
    dcom_dissect_fn_t routine;
} dcom_marshaler_t;

void dcom_get_uuid(uint8_t *pos, bool endian, e_guid_t *guid);
dcom_dissect_fn_t dcom_get_routine_by_uuid(const e_guid_t* uuid);

// Complex type dissectors

ngx_int_t
dissect_dcom_UUID(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    e_guid_t *uuid);

ngx_int_t
dissect_dcom_append_UUID(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    e_guid_t *uuid);

ngx_int_t
dissect_dcom_indexed_WORD(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint16_t *pdata);

ngx_int_t
dissect_dcom_indexed_DWORD(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

ngx_int_t
dissect_dcom_HRESULT(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

ngx_int_t
dissect_dcom_extent(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian);

ngx_int_t
dissect_dcom_HRESULT_item(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

ngx_int_t
dissect_dcom_indexed_HRESULT(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

ngx_int_t
dissect_dcom_COMVERSION(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint16_t *pmajor, uint16_t *pminor);

ngx_int_t
dissect_dcom_dcerpc_array_size(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

ngx_int_t
dissect_dcom_dcerpc_pointer(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

typedef void (*sa_callback_t) (ngx_buf_t *buffer, ngx_int_t offset, bool endian,
    uint32_t var_type, uint32_t array_size);

ngx_int_t
dissect_dcom_SAFEARRAY(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian, sa_callback_t sacb);

ngx_int_t
dissect_dcom_LPWSTR(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    u_char *str, ngx_uint_t *len);

ngx_int_t
dissect_dcom_indexed_LPWSTR(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    u_char *str, ngx_uint_t *len);

ngx_int_t
dissect_dcom_BSTR(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    u_char *str, ngx_uint_t *len);

ngx_int_t
dissect_dcom_DUALSTRINGARRAY(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    unsigned int *ip);

ngx_int_t
dissect_dcom_STDOBJREF(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint64_t *oxid, uint64_t *oid, e_guid_t *ipid);

ngx_int_t
dissect_dcom_CUSTOBJREF(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    e_guid_t *clsid, e_guid_t *iid);

ngx_int_t
dissect_dcom_OBJREF(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

ngx_int_t
dissect_dcom_MInterfacePointer(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

ngx_int_t
dissect_dcom_PMInterfacePointer(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint32_t *pdata);

ngx_int_t
dissect_dcom_VARTYPE(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian,
    uint16_t *pdata);

ngx_int_t
dissect_dcom_tobedone_data(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian, ngx_int_t length);

ngx_int_t
dissect_dcom_nospec_data(ngx_buf_t *buffer,
    ngx_int_t offset, bool endian, ngx_int_t length);

ngx_int_t
dissect_dcom_that(ngx_buf_t *buffer, ngx_int_t offset, bool endian);

ngx_int_t
dissect_dcom_server_alive2(ngx_buf_t *buffer, ngx_int_t offset, bool endian);

ngx_int_t
dissect_dcom_resolve_oxid2(ngx_buf_t *buffer, ngx_int_t offset, bool endian);

ngx_int_t
dissect_dcom_create_instance(ngx_buf_t *buffer, ngx_int_t offset, bool endian);

dcom_resp_t
dissect_dcom_resp_type(ngx_buf_t *buffer, ngx_int_t offset, bool endian);

ngx_int_t
dissect_dcom_precheck(ngx_buf_t *buffer, ngx_int_t offset);

ngx_int_t
dissect_dcom_resp_hdr(ngx_buf_t *buffer, ngx_int_t offset, dcom_resp_t *type, ngx_int_t *endian);

ngx_int_t
dissect_dcom_resp(ngx_buf_t *buffer, ngx_int_t offset, dcom_resp_t type, ngx_int_t endian, bool fixup);

// dcom interface test
void dcom_do_test(void);

#endif /* _PKT_DCOM_H_ */
