#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "jansson.h"
#include <getopt.h>
#include <alloca.h>
#include <assert.h>
#include <time.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-id128.h>
#include <signal.h>
#include <stdint.h>

sd_journal *j = NULL;

// returns allocated copy of value
static char *get_value(const void *data, size_t length) {
	char *sep = strchr(data, '=');
	if (!sep) return NULL;
	size_t valsize = length - (sep - (char*)data + 1) + 1; // excluding '=', including '\0'
	char *ret = malloc(valsize);
	assert(ret);
	memcpy(ret, sep+1, valsize-1);
	ret[valsize-1] = 0;
	return ret;
}

// returns allocated copy of key
static char *get_key(const void *data) {
    char *sep = strchr(data, '=');
    if (!sep) return NULL;
    size_t keysize = (sep - (char*)data) + 2; // including prepended '_', including '\0'
    char *ret = malloc(keysize);
    assert(ret);
    ret[0] = '_';
    memcpy(ret+1, data, keysize-2);
    ret[keysize-1] = 0;
    return ret;
}

char *get_entry_string(){
    const void *data;
    json_t *message = json_object();
    size_t length;

    // journal meta information, prefixed by '__'
    char *cursor;
    uint64_t realtime_usec;
    uint64_t monotonic_usec;
    sd_id128_t boot_id;

    /* mapping from systemd- to GELF- field names */
    const char *fn_sd_host="_HOSTNAME", *fn_gelf_host="host";
    const char *fn_sd_msg="MESSAGE",    *fn_gelf_msg="short_message";
    const char /**fn_sd_time="__REALTIME_TIMESTAMP",*/ *fn_gelf_time="timestamp";
    const char *fn_sd_prio="PRIORITY",  *fn_gelf_prio="level";

    int rc = 0;

    //add version field necessary for GELF
    json_object_set_new(message, "version", json_string("1.1"));

    /* get data necessary for GELF*/

    rc = sd_journal_get_data(j, fn_sd_host, &data, &length);
    if (!rc){
        char *v = get_value(data, length);
	    assert(v);
        json_object_set_new(message, fn_gelf_host, json_string(v));
        free(v);
    }
    else{
        json_object_set_new(message, fn_gelf_host, json_string("not_available"));
    }
    rc = sd_journal_get_data(j, fn_sd_msg, &data, &length);
    if (!rc){
        char *v = get_value(data, length);
        assert(v);
        json_object_set_new(message, fn_gelf_msg, json_string(v));
        free(v);
    }
    else{
        json_object_set_new(message, fn_gelf_msg, json_string("not_available"));
    }
    rc = sd_journal_get_data(j, fn_sd_prio, &data, &length);
    if (!rc){
        char *v = get_value(data, length);
        assert(v);
        int prio = strtol(v, NULL, 10);
        if (prio<0) prio = 0;
        if (prio>7) prio = 7;
        //TODO: log meldung absetzen
        json_object_set_new(message, fn_gelf_prio, json_integer(prio));
        free(v);
    }
    else{
        json_object_set_new(message, fn_gelf_prio, json_string("not_available"));
    }

    // get systemd journal meta fields cursor, realtime- and monotonic timestamp
    // __REALTIME_TIMESTAMP corresponds to  GELF necessary timestamp
    const char *meta_prefixes[] = {"___CURSOR", fn_gelf_time , "___MONOTONIC_TIMESTAMP" };
    sd_journal_get_cursor( j, &cursor );    // needs to be free'd afterwards
    json_object_set_new(message, meta_prefixes[0], json_string(cursor));
    free(cursor);

    sd_journal_get_realtime_usec( j, &realtime_usec );
    json_object_set_new(message, meta_prefixes[1], json_integer(realtime_usec));

    sd_journal_get_monotonic_usec( j, &monotonic_usec, &boot_id);
    json_object_set_new(message, meta_prefixes[2], json_integer(monotonic_usec));

    /* get all remaining fields */
    // (PRIORITY, _HOSTNAME, and MESSAGE are read again)

    // format of prefixes: additional '_' for additional fields in GELF
    // format of retrieved arguments: data="FIELD_NAME=field_value" length=
    SD_JOURNAL_FOREACH_DATA(j, data, length){
        char *v = get_value(data, length);
        assert(v);
        char *k = get_key(data);
        assert(k);
        json_object_set_new(message, k, json_string(v));
        free(v);
        free(k);
    }

    fprintf(stdout, "DBG JSON: %s\n", json_dumps(message, JSON_ENCODE_ANY));
    return NULL;
}

int main (int argc, char *argv[]){
    sd_journal_open(&j, NULL);
    sd_journal_next(j);
    get_entry_string();
    return 0;
}
