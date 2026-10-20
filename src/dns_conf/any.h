#ifndef SMARTDNS_CONF_ANY_H
#define SMARTDNS_CONF_ANY_H
#ifdef __cplusplus
extern "C" {
#endif
int _config_any_mode(void *data, int argc, char *argv[]);
int _config_any_types(void *data, int argc, char *argv[]);
int _config_any_verify(void);
int _config_any_number(void *data, int argc, char *argv[]);
int _config_any_partial(void *data, int argc, char *argv[]);
#ifdef __cplusplus
}
#endif
#endif
