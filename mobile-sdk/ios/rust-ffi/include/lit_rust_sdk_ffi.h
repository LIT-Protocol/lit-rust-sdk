#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Arc_LitClient Arc_LitClient;

typedef struct LitClientHandle {
  struct Arc_LitClient client;
  Runtime runtime;
  NetworkConfig config;
} LitClientHandle;

typedef struct LitAuthContextHandle {
  AuthContext context;
} LitAuthContextHandle;

void lit_free_string(char *s);

struct LitClientHandle *lit_client_create(const char *network_name,
                                          const char *rpc_url,
                                          char **error_out);

void lit_client_destroy(struct LitClientHandle *handle);

int32_t lit_eoa_address_from_private_key(const char *eoa_private_key,
                                         char **result_out,
                                         char **error_out);

struct LitAuthContextHandle *lit_auth_context_create(struct LitClientHandle *client_handle,
                                                     const char *pkp_public_key,
                                                     const char *eoa_private_key,
                                                     uint32_t expiration_minutes,
                                                     char **error_out);

void lit_auth_context_destroy(struct LitAuthContextHandle *handle);

int32_t lit_view_pkps_by_address(struct LitClientHandle *client_handle,
                                 const char *eoa_address,
                                 uint32_t limit,
                                 uint32_t offset,
                                 char **result_out,
                                 char **error_out);

int32_t lit_mint_pkp_with_eoa(struct LitClientHandle *client_handle,
                              const char *eoa_private_key,
                              char **result_out,
                              char **error_out);

int32_t lit_get_balances(struct LitClientHandle *client_handle,
                         const char *eoa_address,
                         char **result_out,
                         char **error_out);

int32_t lit_client_pkp_sign(struct LitClientHandle *client_handle,
                            const char *pkp_public_key,
                            const uint8_t *message_ptr,
                            uintptr_t message_len,
                            struct LitAuthContextHandle *auth_context_handle,
                            char **result_out,
                            char **error_out);
