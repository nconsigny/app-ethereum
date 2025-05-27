#include "typed_data.h"
#include "sol_typenames.h"
#include "apdu_constants.h"  // APDU response codes
#include "context_712.h"
#include "mem.h"
#include "mem_utils.h"

static s_struct_712 *g_structs = NULL;

/**
 * Initialize the typed data context
 *
 * @return whether the memory allocation was successful
 */
bool typed_data_init(void) {
    // TODO
    return true;
}

void typed_data_deinit(void) {
    // TODO : free linked list
    g_structs = NULL;
}

/**
 * Skip TypeDesc from a structure field
 *
 * @param[in] field_ptr pointer to the beginning of the struct field
 * @param[in] ptr pointer to the current location within the struct field
 * @return pointer to the data right after
 */
static const uint8_t *field_skip_typedesc(const uint8_t *field_ptr, const uint8_t *ptr) {
    (void) ptr;
    return field_ptr + sizeof(uint8_t);
}

/**
 * Skip the type name from a structure field
 *
 * @param[in] field_ptr pointer to the beginning of the struct field
 * @param[in] ptr pointer to the current location within the struct field
 * @return pointer to the data right after
 */
static const uint8_t *field_skip_typename(const uint8_t *field_ptr, const uint8_t *ptr) {
    uint8_t size = 0;

    if (struct_field_type(field_ptr) == TYPE_CUSTOM) {
        get_string_in_mem(ptr, &size);
        ptr += (sizeof(size) + size);
    }
    return ptr;
}

/**
 * Skip the type size from a structure field
 *
 * @param[in] field_ptr pointer to the beginning of the struct field
 * @param[in] ptr pointer to the current location within the struct field
 * @return pointer to the data right after
 */
static const uint8_t *field_skip_typesize(const uint8_t *field_ptr, const uint8_t *ptr) {
    if (struct_field_has_typesize(field_ptr)) {
        ptr += sizeof(uint8_t);
    }
    return ptr;
}

/**
 * Skip the array levels from a structure field
 *
 * @param[in] field_ptr pointer to the beginning of the struct field
 * @param[in] ptr pointer to the current location within the struct field
 * @return pointer to the data right after
 */
static const uint8_t *field_skip_array_levels(const uint8_t *field_ptr, const uint8_t *ptr) {
    uint8_t size = 0;

    if (struct_field_is_array(field_ptr)) {
        ptr = get_array_in_mem(ptr, &size);
        while (size-- > 0) {
            ptr = get_next_struct_field_array_lvl(ptr);
        }
    }
    return ptr;
}

/**
 * Skip the key name from a structure field
 *
 * @param[in] field_ptr pointer to the beginning of the struct field
 * @param[in] ptr pointer to the current location within the struct field
 * @return pointer to the data right after
 */
static const uint8_t *field_skip_keyname(const uint8_t *field_ptr, const uint8_t *ptr) {
    uint8_t size = 0;
    uint8_t *new_ptr;

    (void) field_ptr;
    new_ptr = (uint8_t *) get_array_in_mem(ptr, &size);
    return (const uint8_t *) (new_ptr + size);
}

/**
 * Get data pointer & array size from a given pointer
 *
 * @param[in] ptr given pointer
 * @param[out] array_size pointer to array size
 * @return pointer to data
 */
const void *get_array_in_mem(const void *ptr, uint8_t *const array_size) {
    if (ptr == NULL) {
        return NULL;
    }
    if (array_size) {
        *array_size = *(uint8_t *) ptr;
    }
    return (ptr + sizeof(*array_size));
}

/**
 * Get pointer to beginning of string & its length from a given pointer
 *
 * @param[in] ptr given pointer
 * @param[out] string_length pointer to string length
 * @return pointer to beginning of the string
 */
const char *get_string_in_mem(const uint8_t *ptr, uint8_t *const string_length) {
    return (char *) get_array_in_mem(ptr, string_length);
}

/**
 * Get the TypeDesc from a given struct field pointer
 *
 * @param[in] field_ptr struct field pointer
 * @return TypeDesc
 */
static inline uint8_t get_struct_field_typedesc(const uint8_t *const field_ptr) {
    if (field_ptr == NULL) {
        return 0;
    }
    return *field_ptr;
}

/**
 * Check whether a struct field is an array
 *
 * @param[in] field_ptr struct field pointer
 * @return bool whether it is the case
 */
bool struct_field_is_array(const uint8_t *const field_ptr) {
    return (get_struct_field_typedesc(field_ptr) & ARRAY_MASK);
}

/**
 * Check whether a struct field has a type size associated to it
 *
 * @param[in] field_ptr struct field pointer
 * @return bool whether it is the case
 */
bool struct_field_has_typesize(const uint8_t *const field_ptr) {
    return (get_struct_field_typedesc(field_ptr) & TYPESIZE_MASK);
}

/**
 * Get type from a struct field
 *
 * @param[in] field_ptr struct field pointer
 * @return its type enum
 */
e_type struct_field_type(const uint8_t *const field_ptr) {
    return (get_struct_field_typedesc(field_ptr) & TYPE_MASK);
}

/**
 * Get type size from a struct field
 *
 * @param[in] field_ptr struct field pointer
 * @return its type size
 */
uint8_t get_struct_field_typesize(const uint8_t *const field_ptr) {
    if (field_ptr == NULL) {
        return 0;
    }
    return *field_skip_typedesc(field_ptr, NULL);
}

/**
 * Get custom type name from a struct field
 *
 * @param[in] field_ptr struct field pointer
 * @param[out] length the type name length
 * @return type name pointer
 */
const char *get_struct_field_custom_typename(const uint8_t *field_ptr, uint8_t *const length) {
    const uint8_t *ptr;

    if (field_ptr == NULL) {
        return NULL;
    }
    ptr = field_skip_typedesc(field_ptr, NULL);
    return get_string_in_mem(ptr, length);
}

/**
 * Get type name from a struct field
 *
 * @param[in] field_ptr struct field pointer
 * @param[out] length the type name length
 * @return type name pointer
 */
const char *get_struct_field_typename(const uint8_t *field_ptr, uint8_t *const length) {
    if (field_ptr == NULL) {
        return NULL;
    }
    if (struct_field_type(field_ptr) == TYPE_CUSTOM) {
        return get_struct_field_custom_typename(field_ptr, length);
    }
    return get_struct_field_sol_typename(field_ptr, length);
}

/**
 * Get array type of a given struct field's array depth
 *
 * @param[in] array_depth_ptr given array depth
 * @param[out] array_size pointer to array size
 * @return array type of that depth
 */
e_array_type struct_field_array_depth(const uint8_t *array_depth_ptr, uint8_t *const array_size) {
    if (array_depth_ptr == NULL) {
        return 0;
    }
    if (*array_depth_ptr == ARRAY_FIXED_SIZE) {
        if (array_size != NULL) {
            *array_size = *(array_depth_ptr + sizeof(uint8_t));
        }
    }
    return *array_depth_ptr;
}

/**
 * Get next array depth form a given struct field's array depth
 *
 * @param[in] array_depth_ptr given array depth
 * @return next array depth
 */
const uint8_t *get_next_struct_field_array_lvl(const uint8_t *const array_depth_ptr) {
    const uint8_t *ptr;

    if (array_depth_ptr == NULL) {
        return NULL;
    }
    switch (*array_depth_ptr) {
        case ARRAY_DYNAMIC:
            ptr = array_depth_ptr;
            break;
        case ARRAY_FIXED_SIZE:
            ptr = array_depth_ptr + 1;
            break;
        default:
            // should not be in here :^)
            apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            return NULL;
    }
    return ptr + 1;
}

/**
 * Get the array levels from a given struct field
 *
 * @param[in] field_ptr given struct field
 * @param[out] length number of array levels
 * @return pointer to the first array level
 */
const uint8_t *get_struct_field_array_lvls_array(const uint8_t *const field_ptr,
                                                 uint8_t *const length) {
    const uint8_t *ptr;

    if (field_ptr == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    ptr = field_skip_typedesc(field_ptr, NULL);
    ptr = field_skip_typename(field_ptr, ptr);
    ptr = field_skip_typesize(field_ptr, ptr);
    return get_array_in_mem(ptr, length);
}

/**
 * Get key name from a given struct field
 *
 * @param[in] field_ptr given struct field
 * @param[out] length name length
 * @return key name
 */
const char *get_struct_field_keyname(const uint8_t *field_ptr, uint8_t *const length) {
    const uint8_t *ptr;

    if (field_ptr == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    ptr = field_skip_typedesc(field_ptr, NULL);
    ptr = field_skip_typename(field_ptr, ptr);
    ptr = field_skip_typesize(field_ptr, ptr);
    ptr = field_skip_array_levels(field_ptr, ptr);
    return get_string_in_mem(ptr, length);
}

/**
 * Get next struct field from a given field
 *
 * @param[in] field_ptr given struct field
 * @return pointer to the next field
 */
const uint8_t *get_next_struct_field(const void *const field_ptr) {
    const void *ptr;

    if (field_ptr == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    ptr = field_skip_typedesc(field_ptr, NULL);
    ptr = field_skip_typename(field_ptr, ptr);
    ptr = field_skip_typesize(field_ptr, ptr);
    ptr = field_skip_array_levels(field_ptr, ptr);
    return field_skip_keyname(field_ptr, ptr);
}

/**
 * Get name from a given struct
 *
 * @param[in] struct_ptr given struct
 * @param[out] length name length
 * @return struct name
 */
const char *get_struct_name(const uint8_t *const struct_ptr, uint8_t *const length) {
    if (struct_ptr == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    return (char *) get_string_in_mem(struct_ptr, length);
}

/**
 * Get struct fields from a given struct
 *
 * @param[in] struct_ptr given struct
 * @param[out] length number of fields
 * @return struct name
 */
const uint8_t *get_struct_fields_array(const uint8_t *const struct_ptr, uint8_t *const length) {
    const void *ptr;
    uint8_t name_length;

    if (struct_ptr == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    ptr = struct_ptr;
    get_struct_name(struct_ptr, &name_length);
    ptr += (sizeof(name_length) + name_length);  // skip length
    return get_array_in_mem(ptr, length);
}

/**
 * Get next struct from a given struct
 *
 * @param[in] struct_ptr given struct
 * @return pointer to next struct
 */
const uint8_t *get_next_struct(const uint8_t *const struct_ptr) {
    uint8_t fields_count;
    const void *ptr;

    if (struct_ptr == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    ptr = get_struct_fields_array(struct_ptr, &fields_count);
    while (fields_count-- > 0) {
        ptr = get_next_struct_field(ptr);
    }
    return ptr;
}

/**
 * Get structs array
 *
 * @param[out] length number of structs
 * @return pointer to the first struct
 */
const uint8_t *get_structs_array(uint8_t *const length) {
    /*
    return get_array_in_mem(typed_data->structs_array, length);
    */
    // TODO
    (void) length;
    return NULL;
}

/**
 * Find struct with a given name
 *
 * @param[in] name struct name
 * @param[in] length name length
 * @return pointer to struct
 */
const uint8_t *get_structn(const char *const name, const uint8_t length) {
    uint8_t structs_count = 0;
    const uint8_t *struct_ptr;
    const char *struct_name;
    uint8_t name_length;

    if (name == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    struct_ptr = get_structs_array(&structs_count);
    while (structs_count-- > 0) {
        struct_name = get_struct_name(struct_ptr, &name_length);
        if ((length == name_length) && (memcmp(name, struct_name, length) == 0)) {
            return struct_ptr;
        }
        struct_ptr = get_next_struct(struct_ptr);
    }
    apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    return NULL;
}

/**
 * Set struct name
 *
 * @param[in] length name length
 * @param[in] name name
 * @return whether it was successful
 */
bool set_struct_name(uint8_t length, const uint8_t *const name) {
    s_struct_712 *new_struct;

    if (name == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }


    if ((new_struct = app_mem_alloc(sizeof(*new_struct))) == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    explicit_bzero(new_struct, sizeof(*new_struct));

    if ((new_struct->name = app_mem_alloc(length + 1)) == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    new_struct->name[length] = '\0';
    memmove(new_struct->name, name, length);
    struct_state = INITIALIZED;

    // insert into linked list
    if (g_structs == NULL) {
        g_structs = new_struct;
    } else {
        s_struct_712 *s;
        for (s = g_structs; s->next != NULL; s = s->next);
        s->next = new_struct;
    }
    return true;
}

/**
 * Set struct field TypeDesc
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful or not
 */
static bool set_struct_field_typedesc(s_struct_712_field *field,
                                      const uint8_t *const data,
                                      uint8_t *data_idx,
                                      uint8_t length) {
    uint8_t typedesc;

    // copy TypeDesc
    if ((*data_idx + sizeof(typedesc)) > length)  // check buffer bound
    {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    typedesc = data[(*data_idx)++];
    field->type_is_array = typedesc & ARRAY_MASK;
    field->type_has_size = typedesc & TYPESIZE_MASK;
    field->type = typedesc & TYPE_MASK;
    return true;
}

/**
 * Set struct field custom typename
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_custom_typename(s_struct_712_field *field,
                                             const uint8_t *const data,
                                             uint8_t *data_idx,
                                             uint8_t length) {
    uint8_t typename_len;

    // copy custom struct name length
    if ((*data_idx + sizeof(typename_len)) > length)  // check buffer bound
    {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    typename_len = data[(*data_idx)++];

    // copy name
    if ((*data_idx + typename_len) > length)  // check buffer bound
    {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    if ((field->type_name = app_mem_alloc(typename_len + 1)) == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }

    field->type_name[typename_len] = '\0';
    memmove(field->type_name, &data[*data_idx], typename_len);
    *data_idx += typename_len;
    return true;
}

/**
 * Set struct field's array levels
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_array(s_struct_712_field *field,
                                   const uint8_t *const data,
                                   uint8_t *data_idx,
                                   uint8_t length) {
    if ((*data_idx + sizeof(field->array_level_count)) > length)  // check buffer bound
    {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    field->array_level_count = data[(*data_idx)++];
    if ((field->array_levels = app_mem_alloc(sizeof(*field->array_levels) * field->array_level_count)) == NULL) {
        return false;
    }
    for (int idx = 0; idx < field->array_level_count; ++idx) {
        if ((*data_idx + sizeof(field->array_levels[idx].type)) > length)  // check buffer bound
        {
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            return false;
        }
        field->array_levels[idx].type = data[(*data_idx)++];
        switch (field->array_levels[idx].type) {
            case ARRAY_DYNAMIC:  // nothing to do
                break;
            case ARRAY_FIXED_SIZE:
                if ((*data_idx + sizeof(field->array_levels[idx].size)) > length)  // check buffer bound
                {
                    apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                    return false;
                }
                field->array_levels[idx].size = data[(*data_idx)++];
                break;
            default:
                // should not be in here :^)
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
        }
    }
    return true;
}

/**
 * Set struct field's type size
 *
 * @param[in] data the field data
 * @param[in,out] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_typesize(s_struct_712_field *field,
                                      const uint8_t *const data,
                                      uint8_t *data_idx,
                                      uint8_t length) {
    // copy TypeSize
    if ((*data_idx + sizeof(field->type_size)) > length)  // check buffer bound
    {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    field->type_size = data[(*data_idx)++];
    return true;
}

/**
 * Set struct field's key name
 *
 * @param[in] data the field data
 * @param[in,out] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_keyname(s_struct_712_field *field,
                                     const uint8_t *const data,
                                     uint8_t *data_idx,
                                     uint8_t length) {
    uint8_t keyname_len;

    // copy length
    if ((*data_idx + sizeof(keyname_len)) > length)  // check buffer bound
    {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    keyname_len = data[(*data_idx)++];

    // copy name
    if ((*data_idx + keyname_len) > length)  // check buffer bound
    {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    if ((field->key_name = app_mem_alloc(keyname_len + 1)) == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    field->key_name[keyname_len] = '\0';
    memmove(field->key_name, &data[*data_idx], keyname_len);
    *data_idx += keyname_len;
    return true;
}

/**
 * Set struct field
 *
 * @param[in] length data length
 * @param[in] data the field data
 * @return whether it was successful
 */
bool set_struct_field(uint8_t length, const uint8_t *const data) {
    uint8_t data_idx = 0;

    if ((data == NULL) || (length == 0)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    } else if (g_structs == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }

    if (struct_state == NOT_INITIALIZED) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }

    s_struct_712_field *new_field = app_mem_alloc(sizeof(*new_field));
    explicit_bzero(new_field, sizeof(*new_field));

    if (!set_struct_field_typedesc(new_field, data, &data_idx, length)) {
        return false;
    }

    // check TypeSize flag in TypeDesc
    if (new_field->type_has_size) {
        // TYPESIZE and TYPE_CUSTOM are mutually exclusive
        if (new_field->type == TYPE_CUSTOM) {
            apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            return false;
        }

        if (set_struct_field_typesize(new_field, data, &data_idx, length) == false) {
            return false;
        }

    } else if (new_field->type == TYPE_CUSTOM) {
        if (set_struct_field_custom_typename(new_field, data, &data_idx, length) == false) {
            return false;
        }
    }
    if (new_field->type_is_array) {
        if (set_struct_field_array(new_field, data, &data_idx, length) == false) {
            return false;
        }
    }

    if (set_struct_field_keyname(new_field, data, &data_idx, length) == false) {
        return false;
    }

    if (data_idx != length)  // check that there is no more
    {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    // get last struct
    s_struct_712 *s;
    for (s = g_structs; s->next != NULL; s = s->next);

    // insert into linked list
    if (s->fields == NULL) {
        s->fields = new_field;
    } else {
        s_struct_712_field *field;
        for (field = s->fields; field->next != NULL; field = field->next);
        field->next = new_field;
    }
    return true;
}
