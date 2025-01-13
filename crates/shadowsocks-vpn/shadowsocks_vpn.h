#ifndef SHADOWSOCKS_VPN_H
#define SHADOWSOCKS_VPN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

// Opaque type for VPN context
typedef struct VpnContext VpnContext;

// Error codes
typedef enum {
    VPN_ERROR_CONFIG = 1,
    VPN_ERROR_RUNTIME = 2,
    VPN_ERROR_DEVICE = 3
} VpnError;

/**
 * Create a new VPN context with the given configuration
 * @param config_json JSON string containing VPN configuration
 * @return Pointer to VPN context or NULL on error
 */
VpnContext* vpn_create(const char* config_json);

/**
 * Start the VPN tunnel
 * @param context VPN context pointer
 * @return true if successful, false otherwise
 */
bool vpn_start(VpnContext* context);

/**
 * Stop the VPN tunnel
 * @param context VPN context pointer
 * @return true if successful, false otherwise
 */
bool vpn_stop(VpnContext* context);

/**
 * Destroy the VPN context and free resources
 * @param context VPN context pointer
 */
void vpn_destroy(VpnContext* context);

/**
 * Get the last error message
 * @return Error message string. Must be freed by caller.
 */
char* vpn_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* SHADOWSOCKS_VPN_H */