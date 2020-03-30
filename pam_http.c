#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <curl/curl.h>
#include <libconfig.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define BUFSIZE 1024

#define DEFAULT_USER "nobody"
#define DEFAULT_METHOD "GET"
#define DEFAULT_USERNAME_FIELD "username"
#define DEFAULT_PASSWORD_FIELD "password"
#define DEFAULT_HTTP_SUCCESS_CODE 200
#define DEFAULT_CURL_TIMEOUT 10

static const char* HTTP_METHOD_POST = "POST";
static const char* HTTP_METHOD_GET = "GET";

static char password_prompt[] = "Password:";

struct config_auth {
    const char* c_auth_url;
    const char* c_method;
    const char* c_username_field;
    const char* c_password_field;
    long long timeout;
    long long success_code;
};

static void pam_http_syslog(int priority, const char* format, ...)
{
    va_list args;
    va_start(args, format);

    openlog("pam_http", LOG_CONS | LOG_PID, LOG_AUTH);
    vsyslog(priority, format, args);
    closelog();
    va_end(args);
}

static char* config_get_string(config_t* cfg, const char* name, const char* def_value)
{
    const char* value;
    if (!config_lookup_string(cfg, name, &value))
        value = def_value;

    return strndup(value, BUFSIZE);
}

static int read_config_auth(char config_file[BUFSIZE], struct config_auth* s_auth)
{
    config_t cfg;
    const char* buf;

    config_init(&cfg);

    if (!config_read_file(&cfg, config_file)) {
        pam_http_syslog(LOG_ALERT, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return 0;
    }

    if (!config_lookup_string(&cfg, "auth_url", &buf)) {
        pam_http_syslog(LOG_ALERT, "No 'auth_url' setting in configuration file.");
        config_destroy(&cfg);
        return 0;
    }
    s_auth->c_auth_url = strndup(buf, BUFSIZE);

    s_auth->c_method = config_get_string(&cfg, "auth_method", DEFAULT_METHOD);
    if (strncmp(s_auth->c_method, HTTP_METHOD_GET, 3) != 0 && strncmp(s_auth->c_method, HTTP_METHOD_POST, 4) != 0) {
        pam_http_syslog(LOG_ALERT, "Wrong 'auth_method' setting in configuration file (%s).", s_auth->c_method);
        config_destroy(&cfg);
        return 0;
    }

    s_auth->c_username_field = config_get_string(&cfg, "auth_username_field", DEFAULT_USERNAME_FIELD);
    s_auth->c_password_field = config_get_string(&cfg, "auth_password_field", DEFAULT_PASSWORD_FIELD);
    if (!config_lookup_int64(&cfg, "auth_timeout", &s_auth->timeout)) {
        s_auth->timeout = DEFAULT_CURL_TIMEOUT;
    }
    if (!config_lookup_int64(&cfg, "auth_success_code", &s_auth->success_code)) {
        s_auth->success_code = DEFAULT_HTTP_SUCCESS_CODE;
    }

    config_destroy(&cfg);
    return 1;
}

static int pam_http_get_user(pam_handle_t* pamh, const char** user)
{
    int retval;

    retval = pam_get_user(pamh, user, NULL);
    if (retval != PAM_SUCCESS) {
        pam_http_syslog(LOG_ALERT, "pam_get_user returns an error: %s", pam_strerror(pamh, retval));
        return retval;
    }

    if (*user == NULL || **user == '\0') {
        pam_http_syslog(LOG_ALERT, "undefined user");
        retval = pam_set_item(pamh, PAM_USER, (const void*)DEFAULT_USER);
        if (retval != PAM_SUCCESS)
            return PAM_USER_UNKNOWN;
    }

    return retval;
}

static int pam_http_get_password(pam_handle_t* pamh, char** password)
{
    int retval, retry;

    struct pam_conv* conv;
    struct pam_message msg;
    const struct pam_message* msgp;
    struct pam_response* resp;

    retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (retval != PAM_SUCCESS)
        return PAM_SYSTEM_ERR;

    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = password_prompt;
    msgp = &msg;

    for (retry = 0; retry < 3; ++retry) {
        resp = NULL;
        retval = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
        if (resp != NULL) {
            if (retval == PAM_SUCCESS)
                *password = resp->resp;
            else
                free(resp->resp);
            free(resp);
        }

        if (retval == PAM_SUCCESS)
            break;
    }

    if (retval == PAM_CONV_ERR)
        return retval;
    if (retval != PAM_SUCCESS)
        return PAM_AUTH_ERR;

    return PAM_SUCCESS;
}

static int pam_http_request(struct config_auth* s_auth, const char* user, const char* password)
{
    int retval;

    CURL* curl;
    CURLcode res;
    long http_code;

    char auth_url[BUFSIZE];
    char post_fields[BUFSIZE];
    const char *has_parm, *sep;
    char *esc_user, *esc_password;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        esc_user = curl_easy_escape(curl, user, 0);
        esc_password = curl_easy_escape(curl, password, 0);

        if (!esc_user || !esc_password) {
            pam_http_syslog(LOG_ALERT, "could not escape credentials");
            retval = PAM_CRED_ERR;
        } else {
            if (!strncmp(s_auth->c_method, HTTP_METHOD_GET, 3)) {
                has_parm = strstr(s_auth->c_auth_url, "?");
                sep = (has_parm == NULL) ? "?" : "&";
                snprintf(auth_url, BUFSIZE, "%s%s%s=%s&%s=%s", s_auth->c_auth_url, sep,
                    s_auth->c_username_field, esc_user, s_auth->c_password_field, esc_password);
            } else {
                strncpy(auth_url, s_auth->c_auth_url, BUFSIZE);
                snprintf(post_fields, BUFSIZE, "%s=%s&%s=%s", s_auth->c_username_field,
                    esc_user, s_auth->c_password_field, esc_password);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
            }

            curl_easy_setopt(curl, CURLOPT_URL, auth_url);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, s_auth->timeout);

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                pam_http_syslog(LOG_ALERT, "could not perform http request: %s %s:  %s",
                    s_auth->c_method, auth_url, curl_easy_strerror(res));
                retval = PAM_SERVICE_ERR;
            } else {
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                retval = http_code == s_auth->success_code ? PAM_SUCCESS : PAM_AUTH_ERR;
            }

            curl_free(esc_user);
            curl_free(esc_password);
        }

        curl_easy_cleanup(curl);
    } else {
        pam_http_syslog(LOG_ALERT, "could not init curl");
        retval = PAM_SYSTEM_ERR;
    }

    curl_global_cleanup();

    return retval;
}

static int pam_http_authenticate(pam_handle_t* pamh, int argc, const char** argv)
{
    int retval, i;

    char config_file[BUFSIZE];
    struct config_auth s_auth;

    const char* user = NULL;
    char* password;

    for (i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "conf=", 5)) {
            if (argv[i] + 5)
                strncpy(config_file, argv[i] + 5, BUFSIZE - 2);
        }
    }

    if (strlen(config_file) <= 1) {
        pam_http_syslog(LOG_ALERT, "conf directive is not set");
        return PAM_SYSTEM_ERR;
    }

    retval = read_config_auth(config_file, &s_auth);

    if (!retval)
        return PAM_SYSTEM_ERR;

    if ((retval = pam_http_get_user(pamh, &user)) != PAM_SUCCESS)
        return retval;

    if ((retval = pam_http_get_password(pamh, &password)) != PAM_SUCCESS)
        return retval;

    retval = pam_http_request(&s_auth, user, password);

    return retval;
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    return pam_http_authenticate(pamh, argc, argv);
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc,
    const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc,
    const char** argv)
{
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_http_modstruct = {
    "pam_http",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif
