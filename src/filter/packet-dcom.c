#include <ngx_core.h>
#include <nginx.h>

#include <packet-dcom.h>

bool dcom_fixup = false;
bool dcom_align = false;

#define DCOM_MAX_PROPERTY 16
static dcom_dissect_fn_t dissector[DCOM_MAX_PROPERTY];
static ngx_int_t dissector_index;
uint32_t p_property_size_offset[DCOM_MAX_PROPERTY];

// --------------------------------------- dcom interface test ---------------------------------------------
static ngx_int_t dcom_test_data_size = 1056;

static u_char dcom_test_data[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00, 0x20, 0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x08, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x00, 0xf0, 0x03, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x4d, 0x45, 0x4f, 0x57,
    0x04, 0x00, 0x00, 0x00, 0xa3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46, 0x39, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0xb8, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x60, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x39, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0xb6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x02, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00,
    0x18, 0x02, 0x00, 0x00, 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x20, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x02, 0x00,
    0x08, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x50, 0x6d, 0x48, 0x13, 0x21, 0x48, 0xd2, 0x11,
    0xa4, 0x94, 0x3c, 0xb3, 0x06, 0xc1, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00, 0xe4, 0x00, 0x00, 0x00, 0xe4, 0x00, 0x00, 0x00,
    0x4d, 0x45, 0x4f, 0x57, 0x01, 0x00, 0x00, 0x00, 0x50, 0x6d, 0x48, 0x13, 0x21, 0x48, 0xd2, 0x11,
    0xa4, 0x94, 0x3c, 0xb3, 0x06, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0xec, 0x66, 0x09, 0x29, 0x68, 0x07, 0xff, 0x06, 0x97, 0xec, 0x56, 0x8a, 0x0d, 0x33, 0xae, 0xe3,
    0x02, 0xe4, 0x00, 0x00, 0x70, 0x0f, 0xbc, 0x09, 0xaa, 0x4e, 0x07, 0x4a, 0x80, 0x4a, 0x1d, 0xed,
    0x50, 0x00, 0x3d, 0x00, 0x07, 0x00, 0x70, 0x00, 0x72, 0x00, 0x69, 0x00, 0x64, 0x00, 0x65, 0x00,
    0x2d, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x38, 0x00,
    0x2e, 0x00, 0x32, 0x00, 0x34, 0x00, 0x39, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x00, 0x00, 0x07, 0x00,
    0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x38, 0x00, 0x2e, 0x00,
    0x32, 0x00, 0x31, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x00, 0x00, 0x07, 0x00, 0x31, 0x00,
    0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x36, 0x00,
    0x36, 0x00, 0x2e, 0x00, 0x32, 0x00, 0x34, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x10, 0x00, 0xff, 0xff, 0x00, 0x00, 0x0a, 0x00, 0xff, 0xff, 0x00, 0x00,
    0x0e, 0x00, 0xff, 0xff, 0x00, 0x00, 0x11, 0x00, 0xff, 0xff, 0x00, 0x00, 0x12, 0x00, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x08, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xec, 0x66, 0x09, 0x29,
    0x68, 0x07, 0xff, 0x06, 0x04, 0x00, 0x02, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x70, 0x0f, 0xbc, 0x09,
    0x99, 0x5d, 0xb0, 0x25, 0x7e, 0x66, 0xb3, 0x7f, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00,
    0xe7, 0x00, 0x00, 0x00, 0xe7, 0x00, 0x55, 0x00, 0x07, 0x00, 0x70, 0x00, 0x72, 0x00, 0x69, 0x00,
    0x64, 0x00, 0x65, 0x00, 0x2d, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x5b, 0x00, 0x31, 0x00, 0x30, 0x00, 0x35, 0x00, 0x35, 0x00, 0x5d, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x38, 0x00,
    0x2e, 0x00, 0x32, 0x00, 0x34, 0x00, 0x39, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x5b, 0x00, 0x31, 0x00,
    0x30, 0x00, 0x35, 0x00, 0x35, 0x00, 0x5d, 0x00, 0x00, 0x00, 0x07, 0x00, 0x31, 0x00, 0x39, 0x00,
    0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x32, 0x00, 0x31, 0x00,
    0x38, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x5b, 0x00, 0x31, 0x00, 0x30, 0x00, 0x35, 0x00, 0x35, 0x00,
    0x5d, 0x00, 0x00, 0x00, 0x07, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00,
    0x36, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x36, 0x00, 0x36, 0x00, 0x2e, 0x00, 0x32, 0x00, 0x34, 0x00,
    0x31, 0x00, 0x5b, 0x00, 0x31, 0x00, 0x30, 0x00, 0x35, 0x00, 0x35, 0x00, 0x5d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0a, 0x00, 0xff, 0xff, 0x50, 0x00, 0x52, 0x00, 0x49, 0x00, 0x44, 0x00, 0x45, 0x00,
    0x2d, 0x00, 0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x56, 0x00, 0x45, 0x00, 0x52, 0x00, 0x5c, 0x00,
    0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00,
    0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0xff, 0xff,
    0x50, 0x00, 0x52, 0x00, 0x49, 0x00, 0x44, 0x00, 0x45, 0x00, 0x2d, 0x00, 0x53, 0x00, 0x45, 0x00,
    0x52, 0x00, 0x56, 0x00, 0x45, 0x00, 0x52, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6d, 0x00,
    0x69, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00,
    0x6f, 0x00, 0x72, 0x00, 0x00, 0x00, 0x09, 0x00, 0xff, 0xff, 0x50, 0x00, 0x52, 0x00, 0x49, 0x00,
    0x44, 0x00, 0x45, 0x00, 0x2d, 0x00, 0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x56, 0x00, 0x45, 0x00,
    0x52, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x69, 0x00,
    0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x00, 0x00,
    0x11, 0x00, 0xff, 0xff, 0x50, 0x00, 0x52, 0x00, 0x49, 0x00, 0x44, 0x00, 0x45, 0x00, 0x2d, 0x00,
    0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x56, 0x00, 0x45, 0x00, 0x52, 0x00, 0x5c, 0x00, 0x41, 0x00,
    0x64, 0x00, 0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00,
    0x61, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x00, 0x00, 0x12, 0x00, 0xff, 0xff, 0x50, 0x00,
    0x52, 0x00, 0x49, 0x00, 0x44, 0x00, 0x45, 0x00, 0x2d, 0x00, 0x53, 0x00, 0x45, 0x00, 0x52, 0x00,
    0x56, 0x00, 0x45, 0x00, 0x52, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00,
    0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void dcom_do_test(void)
{
    ngx_buf_t buffer, *b;
    ngx_int_t offset, endian;
    dcom_resp_t type;
    filter_dcom_data_t filter, *f;
    u_char iip[] = "1.1.1.1";

    b = &buffer;
    f = &filter;
    ngx_memzero(b, sizeof(ngx_buf_t));
    ngx_memzero(f, sizeof(filter_dcom_data_t));

    b->pos = dcom_test_data;
    b->last = b->pos + dcom_test_data_size;
    b->memory = 1; // buffer in memory flag

    if (dissect_dcom_precheck(b, 0)) {
        return;
    }

    offset = dissect_dcom_resp_hdr(b, 0, &type, &endian);

    f->iport = 1234;
    ngx_memcpy(f->iip, iip, ngx_strlen(iip));
    b->priv = f;

    dissect_dcom_resp(b, offset, type, endian, true);
}

// --------------------------------------- registerd GUID routines ---------------------------------------------
static e_guid_t uuid_isys_activator = {
    UUID_ISYS_ACTIVATOR,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t iid_activate_props_in = {
    IID_ACTI_PROPS_IN,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t iid_activate_props_out = {
    IID_ACTI_PROPS_OUT,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_spec_sys_props = {
    CLSID_SPEC_SYS_PROPS,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_instantiate_info = {
    CLSID_INSTANTIATE_INFO,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_activate_info = {
    CLSID_ACTIVATE_INFO,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_ctx_marshaler = {
    CLSID_CTX_MARSHALER,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_security_info = {
    CLSID_SECURITY_INFO,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_srv_location = {
    CLSID_SRV_LOCATION,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_scm_request = {
    CLSID_SCM_REQUEST,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_props_out = {
    CLSID_PROPS_OUT,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

static e_guid_t clsid_scm_reply = {
    CLSID_SCM_REPLY,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

ngx_int_t
dissect_TypeSzCommPrivHdr(ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t *e)
{
    uint8_t v8;

    /* Common Header */
    // Version
    offset = dissect_dcom_BYTE(buffer, offset, endian, NULL);

    // Endianess
    offset = dissect_dcom_BYTE(buffer, offset, endian, &v8);
    if (v8 == 0x10) { // network little endian
        if (_LITTLE_ENDIAN_) { // host little endian
            endian = true;
        } else {
            endian = false;
        }
    } else { // network big endian
        if (_BIG_ENDIAN_) { // host big endian
            endian = true;
        } else {
            endian = false;
        }
    }

    *e = endian ? 1 : 0;

    // CommonHdrLen
    offset = dissect_dcom_WORD(buffer, offset, endian, NULL);

    // Filter
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // ObjectBufLen
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // Filter
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    return offset;
}

ngx_int_t
dissect_dcom_COMVERSION(ngx_buf_t *buffer, ngx_int_t offset, bool endian,
                        uint16_t *pmajor, uint16_t *pminor)
{
    // Major Version
    offset = dissect_dcom_WORD(buffer, offset, endian, pmajor);

    // Minor Version
    offset = dissect_dcom_WORD(buffer, offset, endian, pminor);

    return offset;
}

ngx_int_t
dissect_dcom_unused_buffer(ngx_buf_t *buffer, ngx_int_t offset, ngx_int_t len, ngx_int_t psize)
{
    u_char tmp[2048], *p, *q;
    ngx_int_t i, left, unused1, unused2;

    unused1 = 0; // modifyed unused
    unused2 = psize - len; // original unused

    if (len % 8) {
        unused1 = 8 - (len % 8);
    }

    ngx_memzero(tmp, 2048);
    p = tmp;
    q = buffer->pos;

    // reserve "front" part
    ngx_memcpy(p, q, offset);
    p += offset;
    q += offset;

    // unused
    for (i = 0; i < unused1; i++) {
        *p = 0x00;
        p++;
    }
    q += unused2;

    // move "left" part
    left = buffer->last - q;
    ngx_memcpy(p, q, left);
    p += left;

    // recover
    ngx_memcpy(buffer->pos, tmp, p - tmp);
    buffer->last = buffer->pos + (p - tmp);

    return offset + unused1;
}

ngx_int_t
dissect_dcom_ScmReplyInfo(ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t index)
{
    ngx_int_t e = 0; // endianess
    uint32_t p_start, p_objbuf_len;
    uint32_t psize, data;
    uint32_t p_array_size;

    p_start = offset;

    offset = dissect_TypeSzCommPrivHdr(buffer, offset, endian, &e);
    if (e) {
        endian = true;
    } else {
        endian = false;
    }
    p_objbuf_len = offset - 8;

    // NULLPtr (0x00000000, receiver ignored)
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // RemoteRequestPtr ReferenceID
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // RemoteReply OXID
    offset = dissect_dcom_ID(buffer, offset, endian, NULL);

    // OxidBindings ReferenceID
    offset = dissect_dcom_dcerpc_array_size(buffer, offset, endian, NULL);

    // UnknownInterfaceID
    offset = dissect_dcom_UUID(buffer, offset, endian, NULL);

    // AuthenticationHint
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // ComVersion
    offset = dissect_dcom_COMVERSION(buffer, offset, endian, NULL, NULL);

    // ArraySize
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);
    p_array_size = offset - 4;

    // OxidBindings DualStringArray
    offset = dissect_dcom_DUALSTRINGARRAY(buffer, offset, endian, &data);
    if (dcom_fixup) {
        // fixup array size
        setv32(buffer->pos + p_array_size, (offset - p_array_size - 8) / 2, endian);
    }

    // UnusedBuffer
    psize = getv32(buffer->pos + p_property_size_offset[index], endian);
    offset = dissect_dcom_unused_buffer(buffer, offset, offset - p_start, psize - data);

    if (dcom_fixup) {
        // fixup objbuf length domain
        setv32(buffer->pos + p_objbuf_len, offset - p_objbuf_len - 8, endian);
    }

    return offset;
}

ngx_int_t
dissect_dcom_PropsOutInfo(ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t index)
{
    ngx_int_t e = 0; // endianess
    uint32_t v32, i;
    uint32_t p_start, p_objbuf_len;
    uint32_t psize, data;
    e_guid_t guid;

    p_start = offset;

    offset = dissect_TypeSzCommPrivHdr(buffer, offset, endian, &e);
    if (e) {
        endian = true;
    } else {
        endian = false;
    }
    p_objbuf_len = offset - 8;

    // NumInterface
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // InterfaceIDsptr ReferenceID
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // ReturnValue ReferenceID
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // InterfacePtrPtr ReferenceID
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // InterfaceIDsPtr MaxCount
    offset = dissect_dcom_DWORD(buffer, offset, endian, &v32);
    for (i = 0; i < v32; i++) {
        // GUID
        offset = dissect_dcom_UUID(buffer, offset, endian, &guid);
    }

    // ReturnValue MaxCount
    offset = dissect_dcom_DWORD(buffer, offset, endian, &v32);
    for (i = 0; i < v32; i++) {
        // ReturnValue
        offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);
    }

    // InterfacePtrPtr MaxCount
    offset = dissect_dcom_DWORD(buffer, offset, endian, &v32);
    for (i = 0; i < v32; i++) {
        // PMInterfacePointer
        offset = dissect_dcom_PMInterfacePointer(buffer, offset, endian, &data);
    }

    // UnusedBuffer
    psize = getv32(buffer->pos + p_property_size_offset[index], endian);
    offset = dissect_dcom_unused_buffer(buffer, offset, offset - p_start, psize - data);

    if (dcom_fixup) {
        // fixup objbuf length domain
        setv32(buffer->pos + p_objbuf_len, offset - p_objbuf_len - 8, endian);
    }

    return offset;
}

ngx_int_t
dissect_dcom_ActivationPropertiesBody(ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t size)
{
    ngx_int_t i, old_offset;

    for (i = 0; i < dissector_index; i++) {
        if (dissector[i]) {
            old_offset = offset;
            offset = dissector[i](buffer, offset, endian, i);
            if (dcom_fixup) {
                // fixup property size domain
                setv32(buffer->pos + p_property_size_offset[i], offset - old_offset, endian);
            }
        }
    }

    return offset;
}

ngx_int_t
dissect_dcom_ActivationPropertiesCustomerHdr(ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t size)
{
    uint32_t p_start, p_custom_hdr_size, p_objbuf_len;
    uint32_t v32, i;
    ngx_int_t e = 0;
    e_guid_t guid;

    p_start = offset;

    // TypeSzCommPrivHdr
    offset = dissect_TypeSzCommPrivHdr(buffer, offset, endian, &e);
    if (e) {
        endian = true;
    } else {
        endian = false;
    }
    p_objbuf_len = offset - 8;

    // TotalSize
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // CustomHdrSize
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);
    p_custom_hdr_size = offset - 4;

    // Reserved
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // DestionationContext
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // ActivationPropertyNumber
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // CLSID
    offset = dissect_dcom_UUID(buffer, offset, endian, NULL);

    // ClsidPtr ReferenceID
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // ClsszPtr ReferenceID
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // NULL pointer
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    dissector_index = 0;

    // ClsidPtr MaxCount
    offset = dissect_dcom_DWORD(buffer, offset, endian, &v32);
    for (i = 0; i < v32; i++) {
        offset = dissect_dcom_UUID(buffer, offset, endian, &guid);
        dissector[dissector_index++] = dcom_get_routine_by_uuid(&guid);
    }

    // ClsszPtr Maxcount
    offset = dissect_dcom_DWORD(buffer, offset, endian, &v32);
    for (i = 0; i < v32; i++) {
        // PropertyDataSize
        offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);
        p_property_size_offset[i] = offset - 4;
    }

    if (dcom_fixup) {
        // fixup custom hdr size
        setv32(buffer->pos + p_custom_hdr_size, offset - p_start, endian);

        // fixup objbuf length domain
        setv32(buffer->pos + p_objbuf_len, offset - p_objbuf_len - 8, endian);
    }

    return offset;
}

ngx_int_t
dissect_dcom_ActivationProperties(ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t size)
{
    uint32_t p_total_size = offset;
    uint32_t p_total_size1;

    // TotalSize
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // Reserved
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    p_total_size1 = offset + 16;

    // CustomHdr
    offset = dissect_dcom_ActivationPropertiesCustomerHdr(buffer, offset, endian, size);

    // PropertyBody
    offset = dissect_dcom_ActivationPropertiesBody(buffer, offset, endian, size);

    if (dcom_fixup) {
        // fixup total size
        setv32(buffer->pos + p_total_size, offset - p_total_size - 8, endian);

        // fixup total size sub
        setv32(buffer->pos + p_total_size1, offset - p_total_size - 8, endian);
    }

    return offset;
}

static dcom_marshaler_t marshaler[] = {
    {NULL, NULL, &uuid_isys_activator, NULL},
    {NULL, NULL, &iid_activate_props_in, dissect_dcom_ActivationProperties},
    {NULL, NULL, &iid_activate_props_out, dissect_dcom_ActivationProperties},
    {NULL, NULL, &clsid_spec_sys_props, NULL},
    {NULL, NULL, &clsid_instantiate_info, NULL},
    {NULL, NULL, &clsid_activate_info, NULL},
    {NULL, NULL, &clsid_ctx_marshaler, NULL},
    {NULL, NULL, &clsid_security_info, NULL},
    {NULL, NULL, &clsid_srv_location, NULL},
    {NULL, NULL, &clsid_scm_request, NULL},
    {NULL, NULL, &clsid_props_out, dissect_dcom_PropsOutInfo},
    {NULL, NULL, &clsid_scm_reply, dissect_dcom_ScmReplyInfo}
};

#define MARSHALER_MAX sizeof(marshaler) / sizeof(marshaler[0])

void
dcom_get_uuid(uint8_t *pos, bool endian, e_guid_t *guid)
{
    uint8_t *ptr = pos;
    guid->data1 = getv32(ptr + 0, endian);
    guid->data2 = getv16(ptr + 4, endian);
    guid->data3 = getv16(ptr + 6, endian);
    memcpy(guid->data4, ptr + 8, sizeof guid->data4);
}

dcom_dissect_fn_t
dcom_get_routine_by_uuid(const e_guid_t *guid)
{
    ngx_uint_t i;
    for (i = 0; i < MARSHALER_MAX; i++) {
        if (!ngx_memcmp(guid, marshaler[i].uuid, sizeof(e_guid_t))) {
            return marshaler[i].routine;
        }
    }
    return NULL;
}

// --------------------------------------- Simple type dissectors ---------------------------------------------
static ngx_int_t
dissect_dcerpc_uint8(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint8_t *pdata)
{
    uint8_t data = getv8(buffer->pos + offset);
    if (pdata) {
        *pdata = data;
    }
    return offset + 1;
}

static ngx_int_t
dissect_dcerpc_uint16(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint16_t *pdata)
{
    uint16_t data = getv16(buffer->pos + offset, endian);
    if (pdata) {
        *pdata = data;
    }
    return offset + 2;
}

static ngx_int_t
dissect_dcerpc_uint32(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    uint32_t data = getv32(buffer->pos + offset, endian);
    if (pdata) {
        *pdata = data;
    }
    return offset + 4;
}

static ngx_int_t
dissect_dcerpc_uint64(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint64_t *pdata)
{
    uint64_t data = getv64(buffer->pos + offset, endian);
    if (pdata) {
        *pdata = data;
    }
    return offset + 8;
}

static ngx_int_t
dissect_dcerpc_float(ngx_buf_t *buffer, ngx_int_t offset, bool endian, float *pdata)
{
    // not supported yet
    return offset + 4;
}

static ngx_int_t
dissect_dcerpc_double(ngx_buf_t *buffer, ngx_int_t offset, bool endian, double *pdata)
{
    // not supported yet
    return offset + 8;
}

static ngx_int_t
dissect_dcerpc_time_t(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    // not supported yet
    return offset + 4;
}

static ngx_int_t
dissect_dcerpc_uuid_t(ngx_buf_t *buffer, ngx_int_t offset, bool endian, e_guid_t *pdata)
{
    e_guid_t uuid;
    dcom_get_uuid(buffer->pos + offset, endian, &uuid);
    if (pdata) {
        *pdata = uuid;
    }
    return offset + 16;
}

ngx_int_t
dissect_ndr_uint8(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint8_t *pdata)
{
    if (pdata) {
        *pdata = 0;
    }
    return dissect_dcerpc_uint8(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_ndr_uint16(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint16_t *pdata)
{
    if (pdata) {
        *pdata = 0;
    }
    if (dcom_align && offset % 2) {
        offset++;
    }
    return dissect_dcerpc_uint16(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_ndr_uint32(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    if (pdata) {
        *pdata = 0;
    }
    if (dcom_align && offset % 4) {
        offset += 4 - (offset % 4);
    }
    return dissect_dcerpc_uint32(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_ndr_duint32(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint64_t *pdata)
{
    if (pdata) {
        *pdata = 0;
    }
    if (dcom_align && offset % 4) {
        offset += 4 - (offset % 4);
    }
    return dissect_dcerpc_uint64(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_ndr_uint64(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint64_t *pdata)
{
    if (pdata) {
        *pdata = 0;
    }
    if (dcom_align && offset % 8) {
        offset += 8 - (offset % 8);
    }
    return dissect_dcerpc_uint64(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_ndr_float(ngx_buf_t *buffer, ngx_int_t offset, bool endian, float *pdata)
{
    if (pdata) {
        *pdata = 0;
    }
    if (dcom_align && offset % 4) {
        offset += 4 - (offset % 4);
    }
    return dissect_dcerpc_float(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_ndr_double(ngx_buf_t *buffer, ngx_int_t offset, bool endian, double *pdata)
{
    if (pdata) {
        *pdata = 0;
    }
    if (dcom_align && offset % 8) {
        offset += 8 - (offset % 8);
    }
    return dissect_dcerpc_double(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_ndr_time_t(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    if (pdata) {
        *pdata = 0;
    }
    if (dcom_align && offset % 4) {
        offset += 4 - (offset % 4);
    }
    return dissect_dcerpc_time_t(buffer, offset, endian, pdata);
}

static ngx_int_t
dissect_ndr_uuid_t(ngx_buf_t *buffer, ngx_int_t offset, bool endian, e_guid_t *pdata)
{
    if (pdata) {
        memset(pdata, 0, sizeof(*pdata));
    }
    return dissect_dcerpc_uuid_t(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_dcom_UUID(ngx_buf_t *buffer, ngx_int_t offset, bool endian, e_guid_t *pdata)
{
    e_guid_t uuid;
    offset = dissect_ndr_uuid_t(buffer, offset, endian, &uuid);
    if(pdata != NULL) {
        *pdata = uuid;
    }
    return offset;
}

ngx_int_t
dissect_dcom_append_UUID(ngx_buf_t *buffer, ngx_int_t offset, bool endian, e_guid_t *uuid)
{
    return dissect_ndr_uuid_t(buffer, offset, endian, uuid);
}

ngx_int_t
dissect_dcom_dcerpc_array_size(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    return dissect_ndr_uint32(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_dcom_dcerpc_pointer(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *p32)
{
    return dissect_ndr_uint32(buffer, offset, endian, p32);
}

static ngx_int_t
dcom_buffer_get_nwstringz0(ngx_buf_t *buffer, ngx_int_t offset, u_char *str, ngx_uint_t *len)
{
    uint8_t v8_1;
    uint8_t v8_2;
    ngx_uint_t i, l;

    l = 0;

    for (i = 0; i < 1024; i += 2) {
        v8_1 = getv8(buffer->pos + offset + i);
        v8_2 = getv8(buffer->pos + offset + i + 1);

        /* is this the zero termination? */
        if (v8_1 == 0 && v8_2 == 0) {
            i += 2;
            break;
        }

        /* extract printable text, see ASCII */
        if (v8_1 >= 33 && v8_1 <= 126) {
            str[l++] = v8_1;
        }
        if (v8_2 >= 33 && v8_2 <= 126) {
            str[l++] = v8_2;
        }
    }

    *len = l;
    return offset + i;
}

ngx_int_t
dissect_dcom_VARTYPE(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint16_t *pdata)
{
    return dissect_dcom_WORD(buffer, offset, endian, pdata);
}

// --------------------------------------- Complex type dissectors ---------------------------------------------
ngx_int_t
dissect_dcom_tobedone_data(ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t length)
{
    // not supported yet
    return offset + length;
}

ngx_int_t
dissect_dcom_indexed_WORD(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint16_t *pdata)
{
    return dissect_dcom_WORD(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_dcom_indexed_DWORD(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    return dissect_dcom_DWORD(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_dcom_BSTR(ngx_buf_t *buffer, ngx_int_t offset, bool endian,
    u_char *str, ngx_uint_t *len)
{
    ngx_int_t real_offset;
    uint32_t asize;

    /* alignment of 4 needed */
    if (offset % 4) {
        offset += 4 - (offset % 4);
    }

    // MaxCount
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // ByteLength
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // ArraySize
    offset = dissect_dcom_dcerpc_array_size(buffer, offset, endian, &asize);

    real_offset = offset + asize * 2;

    offset = dcom_buffer_get_nwstringz0(buffer, offset, str, len);

    return real_offset;
}

ngx_int_t
dissect_dcom_indexed_LPWSTR(ngx_buf_t *buffer, ngx_int_t offset, bool endian,
    u_char *str, ngx_uint_t *len)
{
    /* alignment of 4 needed */
    if (offset % 4) {
        offset += 4 - (offset % 4);
    }

    // MaxCount
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // Offset
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // ArraySize
    offset = dissect_dcom_dcerpc_array_size(buffer, offset, endian, NULL);

    // String
    offset = dcom_buffer_get_nwstringz0(buffer, offset, str, len);

    return offset;
}

ngx_int_t
dissect_dcom_LPWSTR(ngx_buf_t *buffer, ngx_int_t offset, bool endian,
    u_char *str, ngx_uint_t *len)
{
    return dissect_dcom_indexed_LPWSTR(buffer, offset, endian, str, len);
}

ngx_int_t
dissect_dcom_DUALSTRINGARRAY(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    u_char str[1024];
    ngx_uint_t len;
    uint32_t p32sub, p32sub2;
    uint32_t p32_sec_offest;
    u_char *p, *q;
    bool have_port = false;
    bool first = true;

    filter_dcom_data_t *d = (filter_dcom_data_t *)buffer->priv;

    // NumEntries  (STRINGBINDINGsLength + SECURITYBINDINGsLength) / 2
    offset = dissect_dcom_WORD(buffer, offset, endian, NULL);

    /* from here, alignment is ok */
    p32sub = offset - 2; // p32_num_entries

    // SecurityOffset  (STRINGBINDINGsLength) / 2
    offset = dissect_dcom_WORD(buffer, offset, endian, NULL);
    p32_sec_offest = offset - 2;

    /* STRINGBINDINGs until first wchar zero */
    p32sub2 = offset;

    while (getv16(buffer->pos + offset, endian)) {
        ngx_memzero(str, 1024);

        // TowerID
        offset = dissect_dcom_WORD(buffer, offset, endian, NULL);

        // NetworkString (SERVERNAME or IP, terminated with 0x0000)
        offset = dcom_buffer_get_nwstringz0(buffer, offset, str, &len);

        if (dcom_fixup) {
            // first stringbingding contain hostname
            if (first) {
                p = (u_char *)ngx_strchr(str, '[');
                if (p) { // has port in format: hostname[port]
                    ngx_memcpy(d->oip, str, p - str);
                } else { // only hostname
                    ngx_memcpy(d->oip, str, ngx_strlen(str));
                }
                first = false;
            }

            // extract port
            if (d && !d->oport) { // do once
                u_char port[64] = {0};
                p = (u_char *)ngx_strchr(str, '[');
                q = (u_char *)ngx_strchr(str, ']');
                if (p && q) {
                    p += 1;
                    q -= 1;
                    ngx_memcpy(port, p, q - p + 1);
                    d->oport = atoi((const char *)port);
                    have_port = true;
                }
            }
        }
    }

    // 0x0000
    offset += 2;

    if (dcom_fixup) {
        u_char tmp[256] = {0};
        u_char buf[2048] = {0};
        u_char port_str[64];
        ngx_int_t i, l, buf_len;
        p = tmp;

        #if 0
        // TowerID
        setv16(p, 0x0007, endian);
        p += 2;
        // HostName
        l = ngx_strlen(d->oip);
        for (i = 0; i < l; i++) {
            p[0] = d->oip[i];
            p[1] = 0x00;
            p += 2;
        }
        // PORT (if '[' and ']' found in oringnal stringbinds)
        if (have_port) {
            ngx_memzero(port_str, 64);
            p[0] = 0x5b; // '['
            p[1] = 0x00;
            p += 2;
            ngx_sprintf(port_str, "%ud", d->iport);
            l = ngx_strlen(port_str);
            for (i = 0; i < l; i++) {
                p[0] = port_str[i];
                p[1] = 0x00;
                p += 2;
            }
            p[0] = 0x5d; // ']'
            p[1] = 0x00;
            p += 2;
        }
        // terminate 0x0000
        p[0] = 0x00;
        p[1] = 0x00;
        p += 2;
        #endif

        // TowerID
        setv16(p, 0x0007, endian);
        p += 2;
        // IP
        l = ngx_strlen(d->iip);
        for (i = 0; i < l; i++) {
            p[0] = d->iip[i];
            p[1] = 0x00;
            p += 2;
        }
        // PORT (if '[' and ']' found in oringnal stringbinds)
        if (have_port) {
            ngx_memzero(port_str, 64);
            p[0] = 0x5b; // '['
            p[1] = 0x00;
            p += 2;
            ngx_sprintf(port_str, "%ud", d->iport);
            l = ngx_strlen(port_str);
            for (i = 0; i < l; i++) {
                p[0] = port_str[i];
                p[1] = 0x00;
                p += 2;
            }
            p[0] = 0x5d; // ']'
            p[1] = 0x00;
            p += 2;
        }
        // terminate 0x00000000
        p[0] = 0x00;
        p[1] = 0x00;
        p[2] = 0x00;
        p[3] = 0x00;
        p += 4;

        l = p - tmp;

        // replace old data
        buf_len = ngx_buf_size(buffer) - offset;
        ngx_memcpy(buf, buffer->pos + offset, buf_len);
        ngx_memcpy(buffer->pos + p32sub2, tmp, l);
        ngx_memcpy(buffer->pos + p32sub2 + l, buf, buf_len);
        buffer->last = buffer->pos + p32sub2 + l + buf_len;

        offset = p32sub2 + l;
    }

    if (dcom_fixup) {
        // fixup security offset
        if (pdata) {
            *pdata = getv16(buffer->pos + p32_sec_offest, endian) * 2 - (offset - p32sub2);
        }
        setv16(buffer->pos + p32_sec_offest, (offset - p32sub2) / 2, endian);
    }

    /* SECURITYBINDINGs until first wchar zero */
    while (getv16(buffer->pos + offset, endian)) {
        // SecurityAuthnSvc
        offset = dissect_dcom_WORD(buffer, offset, endian, NULL);

        // SecurityAuthzSvc
        offset = dissect_dcom_WORD(buffer, offset, endian, NULL);

        // PrincName
        offset = dcom_buffer_get_nwstringz0(buffer, offset, str, &len);
    }

    // 0x0000
    offset += 2;

    if (dcom_fixup) {
        // fixup number entries
        setv16(buffer->pos + p32sub, (offset - p32sub2) / 2, endian);
    }

    return offset;
}

ngx_int_t
dissect_dcom_STDOBJREF(ngx_buf_t *buffer, ngx_int_t offset, bool endian,
    uint64_t *oxid, uint64_t *oid, e_guid_t *ipid)
{
    // Flags
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // PublicRefs
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // OXID
    offset = dissect_dcom_ID(buffer, offset, endian, oxid);

    // OID
    offset = dissect_dcom_ID(buffer, offset, endian, oid);

    // IPID
    offset = dissect_dcom_UUID(buffer, offset, endian, ipid);

    return offset;
}

ngx_int_t
dissect_dcom_CUSTOBJREF(ngx_buf_t *buffer, ngx_int_t offset, bool endian,
    e_guid_t *clsid, e_guid_t *iid)
{
    dcom_dissect_fn_t routine = NULL;
    uint32_t p_size;

    // CLSID
    offset = dissect_dcom_UUID(buffer, offset, endian, clsid);

    // CBExtension
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // Size
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);
    p_size = offset - 4;

    // IID fallback
    routine = dcom_get_routine_by_uuid(iid);
    if (routine) {
        offset = routine(buffer, offset, endian, 0);
    }

    if (dcom_fixup) {
        // fixup size domain
        setv32(buffer->pos + p_size, offset - p_size - 4, endian);
    }

    return offset;
}

ngx_int_t
dissect_dcom_OBJREF(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    e_guid_t iid, clsid, ipid;
    uint32_t v32;
    uint64_t oxid, oid;

    ngx_memzero(&iid, sizeof(e_guid_t));
    ngx_memzero(&clsid, sizeof(e_guid_t));
    ngx_memzero(&ipid, sizeof(e_guid_t));
    oxid = oid = 0;

    // OBJREF SIGNATURE
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // OBJREF flags
    offset = dissect_dcom_DWORD(buffer, offset, endian, &v32);

    // OBJREF iid
    offset = dissect_dcom_UUID(buffer, offset, endian, &iid);

    switch (v32) {
        case OBJREF_FLAGS_STANDARD:
            offset = dissect_dcom_STDOBJREF(buffer, offset, endian, &oxid, &oid, &ipid);
            offset = dissect_dcom_DUALSTRINGARRAY(buffer, offset, endian, pdata);
            break;
        case OBJREF_FLAGS_HANDLER:
            offset = dissect_dcom_STDOBJREF(buffer, offset, endian, &oxid, &oid, &iid);
            offset = dissect_dcom_UUID(buffer, offset, endian, &clsid);
            offset = dissect_dcom_DUALSTRINGARRAY(buffer, offset, endian, pdata);
            break;
        case OBJREF_FLAGS_CUSTOM:
            offset = dissect_dcom_CUSTOBJREF(buffer, offset, endian, &clsid, &iid);
            break;
    }

    return offset;
}

ngx_int_t
dissect_dcom_MInterfacePointer(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    uint32_t p_cnt_data;

    // ArraySize
    offset = dissect_dcom_dcerpc_array_size(buffer, offset, endian, NULL);

    // CountData
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);
    p_cnt_data = offset - 4;

    // OBJREF
    offset = dissect_dcom_OBJREF(buffer, offset, endian, pdata);

    if (dcom_fixup) {
        // fixup count data domain
        setv32(buffer->pos + p_cnt_data, offset - p_cnt_data - 4, endian);
        // fix bug: some implementation set reserved same as count data
        setv32(buffer->pos + p_cnt_data - 4, offset - p_cnt_data - 4, endian);
    }

    return offset;
}

ngx_int_t
dissect_dcom_PMInterfacePointer(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    uint32_t v32;

    offset = dissect_dcom_dcerpc_pointer(buffer, offset, endian, &v32);

    if (v32) {
        offset = dissect_dcom_MInterfacePointer(buffer, offset, endian, pdata);
    }

    return offset;
}

ngx_int_t
dissect_dcom_HRESULT(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    uint32_t data;

    offset = dissect_dcom_DWORD(buffer, offset, endian, &data);
    if (pdata) {
        *pdata = data;
    }
    return offset;
}

ngx_int_t
dissect_dcom_HRESULT_item(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    return dissect_dcom_HRESULT(buffer, offset, endian, pdata);
}

ngx_int_t
dissect_dcom_indexed_HRESULT(ngx_buf_t *buffer, ngx_int_t offset, bool endian, uint32_t *pdata)
{
    return dissect_dcom_HRESULT(buffer, offset, endian, pdata);
}


ngx_int_t
dissect_dcom_nospec_data(ngx_buf_t *buffer, ngx_int_t offset, bool endian, ngx_int_t length)
{
    // not supported yet
    return offset + length;
}

ngx_int_t
dissect_dcom_extent(ngx_buf_t *buffer, ngx_int_t offset, bool endian)
{
    uint32_t v32;
    uint32_t asize, asize2, var_offset;

    // Pointer
    offset = dissect_dcom_dcerpc_pointer(buffer, offset, endian, &v32);

    if (!v32) {
        return offset;
    }

    // ArrayCount
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // Reserved
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // Pointer
    offset = dissect_dcom_dcerpc_pointer(buffer, offset, endian, &v32);

    if (!v32) {
        return offset;
    }

    // ArraySize
    offset = dissect_dcom_dcerpc_array_size(buffer, offset, endian, &asize);

    var_offset = offset + asize * 4;

    while (asize--) {
        // Pointer
        offset = dissect_dcom_dcerpc_pointer(buffer, offset, endian, &v32);

        if (v32) {
            var_offset = dissect_dcom_DWORD(buffer, var_offset, endian, NULL);

            // UUID
            var_offset = dissect_dcom_UUID(buffer, var_offset, endian, NULL);

            // ArraySize
            var_offset = dissect_dcom_dcerpc_array_size(buffer, var_offset, endian, &asize2);

            // ArraySize
            var_offset = dissect_dcom_nospec_data(buffer, var_offset, endian, asize2);
        } else {
            ;
        }
    }

    return var_offset;
}

ngx_int_t
dissect_dcom_that(ngx_buf_t *buffer, ngx_int_t offset, bool endian)
{
    // Flags
    offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

    // Extent
    offset = dissect_dcom_extent(buffer, offset, endian);

    return offset;
}

ngx_int_t
dissect_dcom_server_alive2(ngx_buf_t *buffer, ngx_int_t offset, bool endian)
{
    uint32_t v32, p_array_size;

    // NGX_PRINT_HEX(buffer->pos, ngx_buf_size(buffer), "1");

    // ComVersion
    offset = dissect_dcom_COMVERSION(buffer, offset, endian, NULL, NULL);

    // Pointer
    offset = dissect_dcom_dcerpc_pointer(buffer, offset, endian, &v32);
    if (v32) {
        // ArraySize
        offset = dissect_dcom_dcerpc_array_size(buffer, offset, endian, NULL);
        p_array_size = offset - 4;

        // DualString
        offset = dissect_dcom_DUALSTRINGARRAY(buffer, offset, endian, NULL);
        if (dcom_fixup) {
            // fixup array size
            setv32(buffer->pos + p_array_size, (offset - p_array_size - 8) / 2, endian);
        }
    }

    // UnknownField
    offset = dissect_dcerpc_uint64(buffer, offset, endian, NULL);

    return offset;
}

static ngx_int_t
dissect_dcom_dualstring_align(ngx_buf_t *buffer, ngx_int_t offset, ngx_int_t size1, ngx_int_t size2)
{
    ngx_int_t align1, align2;
    u_char buf[2048], *p, *q;

    align1 = align2 = 0;

    if (size1 % 4) {
        align1 = 4 - (size1 % 4); // orignal alignment
    }

    if (size2 % 4) {
        align2 = 4 - (size2 % 4); // new alignment
    }

    if (align1 == align2) { // same alignment, do nothing
        return offset + align1;
    }

    NGX_PRINT("size1 %d size2 %d align1 %d align2 %d bsize %d offset %d\n",
        size1, size2, align1, align2, ngx_buf_size(buffer), offset);

    ngx_memzero(buf, 2048);
    p = buf;

    // reserve "front" part (from buffer's start to dualstring's end)
    q = buffer->pos + offset;

    // new align (if any, maybe 0)
    p += align2;

    // adhere "left" part (from align's end to buffer's end)
    ngx_memcpy(p, q + align1, ngx_buf_size(buffer) - offset - align1);
    p += ngx_buf_size(buffer) - offset - align1;

    // recover
    ngx_memcpy(q, buf, p - buf);
    buffer->last = buffer->pos + offset + (p - buf);

    return offset + align2;
}

ngx_int_t
dissect_dcom_resolve_oxid2(ngx_buf_t *buffer, ngx_int_t offset, bool endian)
{
    uint32_t v32, p_array_size;

    // NGX_PRINT_HEX(buffer->pos, ngx_buf_size(buffer), "1");

    // Pointer
    offset = dissect_dcom_dcerpc_pointer(buffer, offset, endian, &v32);
    if (v32) {
        // ArraySize
        offset = dissect_dcom_dcerpc_array_size(buffer, offset, endian, &v32);
        p_array_size = offset - 4;

        // DualString
        offset = dissect_dcom_DUALSTRINGARRAY(buffer, offset, endian, NULL);
        if (dcom_fixup) {
            // fixup array size
            setv32(buffer->pos + p_array_size, (offset - p_array_size - 8) / 2, endian);
        }

        /**
         * FIXME:
         * dualstring 4 bytes align?
         */
        offset = dissect_dcom_dualstring_align(buffer, offset, v32 * 2 + 4, offset - p_array_size - 4);

        // UUID
        offset = dissect_dcom_UUID(buffer, offset, endian, NULL);

        // AuthHint
        offset = dissect_dcom_DWORD(buffer, offset, endian, NULL);

        // ComVersion
        offset = dissect_dcom_COMVERSION(buffer, offset, endian, NULL, NULL);
    }

    // HResult
    offset = dissect_dcom_HRESULT(buffer, offset, endian, NULL);

    return offset;
}

ngx_int_t
dissect_dcom_create_instance(ngx_buf_t *buffer, ngx_int_t offset, bool endian)
{
    // NGX_PRINT_HEX(buffer->pos, ngx_buf_size(buffer), "1");

    // ORPCthat
    offset = dissect_dcom_that(buffer, offset, endian);

    // PMInterfacePointer
    offset = dissect_dcom_PMInterfacePointer(buffer, offset, endian, NULL);

    // HResult
    offset = dissect_dcom_HRESULT(buffer, offset, endian, NULL);

    return offset;
}

dcom_resp_t
dissect_dcom_resp_type(ngx_buf_t *buffer, ngx_int_t offset, bool endian)
{
    uint16_t v16_1, v16_2;
    uint32_t v32_1, v32_2;
    uint8_t *p;

    // ServerAlive2?
    p = (uint8_t *)(buffer->pos + offset);
    v16_1 = getv16(p, endian);
    p += 2;
    v16_2 = getv16(p, endian);
    p += 2;

    if ((v16_1 == 5) && (v16_2 == 7)) {
        // reference ID
        v32_1 = getv32(p, endian);
        p += 4;

        // ArraySize
        v32_2 = getv32(p, endian);
        p += 4;

        // EnumEntries
        v16_1 = getv16(p, endian);

        if ((v32_1 == 0x00020000) && ((uint16_t)v32_2 == v16_1)) {
            NGX_PRINT("ServerAlive2\n");
            return DCOM_RESP_SERVER_ALIVE2;
        }
    }

    // ResolveOxid2?
    p = (uint8_t *)(buffer->pos + offset);
    // reference ID
    v32_1 = getv32(p, endian);
    p += 4;

    // ArraySize
    v32_2 = getv32(p, endian);
    p += 4;

    // EnumEntries
    v16_1 = getv16(p, endian);

    if ((v32_1 == 0x00020000) && ((uint16_t)v32_2 == v16_1)) {
        NGX_PRINT("ResolveOxid2\n");
        return DCOM_RESP_RESOLVE_OXID2;
    }

    // CreateInstance?
    p = (uint8_t *)(buffer->pos + offset);
    // InfoLocal Flag
    v32_1 = getv32(p, endian);
    p += 4;

    // Pointer
    v32_2 = getv32(p, endian);
    p += 4;

    if (((v32_1 == 0) || (v32_1 == 1)) && (v32_2== 0)) {
        // ReferenceID
        v32_1 = getv32(p, endian);
        if (v32_1 == 0x00020000) {
            NGX_PRINT("CreateInstance\n");
            return DCOM_RESP_CREATE_INSTANCE;
        }
    }

    return DCOM_RESP_UNKNOWN;
}

ngx_int_t
dissect_dcom_precheck(ngx_buf_t *buffer, ngx_int_t offset)
{
    dce_common_hdr_t *hdr = (dce_common_hdr_t *)(buffer->pos + offset);
    if (hdr->rpc_ver != 5) {
        return NGX_DECLINED;
    }
    if (hdr->rpc_ver_minor != 0 && hdr->rpc_ver_minor != 1) {
        return NGX_DECLINED;
    }
    if (hdr->ptype != 2) { // not response PDU
        return NGX_DECLINED;
    }
    return NGX_OK;
}

ngx_int_t
dissect_dcom_resp_hdr(ngx_buf_t *buffer, ngx_int_t offset, dcom_resp_t *type, ngx_int_t *endian)
{
    dcom_resp_t _type;
    ngx_int_t _endian;

    // DCE/RPC header
    dce_common_hdr_t *hdr = (dce_common_hdr_t *)(buffer->pos + offset);
    if ((hdr->drep[0] >> 4) == 0x1) { // network little endian
        if (_LITTLE_ENDIAN_) { // host little endian
            _endian = 1; // same
        } else {
            _endian = 0; // not same
        }
    } else { // network big endian
        if (_BIG_ENDIAN_) { // host big endian
            _endian = 1; // same
        } else {
            _endian = 0; // not same
        }
    }
    offset += DCE_COMMON_HDR_SIZE + DCE_RESP_SPEC_HDR_SIZE;

    _type = dissect_dcom_resp_type(buffer, offset, endian);

    if (type) {
        *type = _type;
    }
    if (endian) {
        *endian = _endian;
    }

    return offset;
}

ngx_int_t
dissect_dcom_resp(ngx_buf_t *buffer, ngx_int_t offset, dcom_resp_t type, ngx_int_t endian, bool fixup)
{
    uint32_t p_start = offset - DCE_COMMON_HDR_SIZE - DCE_RESP_SPEC_HDR_SIZE; // start from header
    bool _endian = endian ? true : false;
    ngx_int_t rv = NGX_DECLINED; // ignored

    dcom_fixup = fixup;

    switch (type) {
        case DCOM_RESP_SERVER_ALIVE2:
            offset = dissect_dcom_server_alive2(buffer, offset, _endian);
            break;
        case DCOM_RESP_RESOLVE_OXID2:
            offset = dissect_dcom_resolve_oxid2(buffer, offset, _endian);
            rv = NGX_OK;
            break;
        case DCOM_RESP_CREATE_INSTANCE:
            offset = dissect_dcom_create_instance(buffer, offset, _endian);
            rv = NGX_OK;
            break;
        case DCOM_RESP_UNKNOWN:
            return rv;
        default:
            return rv;
    }

    if (dcom_fixup) {
        // fixup frag length domain
        setv16(buffer->pos + 8, offset - p_start, _endian);
    }

    // NGX_PRINT_HEX(buffer->pos, ngx_buf_size(buffer), "2");

    return rv;
}