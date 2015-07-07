#include "stdio.h"
#include "stdint.h"
#include "minunit/minunit.h"
#define TEST
#include "../src/journal-gateway-zmtp-sink.c"

int tests_run = 0;

MU_TEST(test_get_arg_string)
{
	char *ret,
	*i1 = "YaxPLAFYM5",
	*i2 = "4yCSnjc68q",
	*i3 = "cWnCwwWmAV";
	json_t *o;

	o = json_string(i1);
	ret = get_arg_string(o);
	mu_assert(!strcmp(ret, i1),"string unpacking from json object failed");
	free(o);
	free(ret);

	o = json_string(i2);
	ret = get_arg_string(o);
	mu_assert(!strcmp(ret, i2),"string unpacking from json object failed");
	free(o);
	free(ret);

	o = json_string(i3);
	ret = get_arg_string(o);
	mu_assert(!strcmp(ret, i3),"string unpacking from json object failed");
	free(o);
	free(ret);

	return NULL;
}

MU_TEST(test_make_json_timestamp)
{
	char *ret,
	*i1 = NULL,	*o1 = NULL,
	*i2 = strdup("now"), *o2 = "now",
	*i3 = strdup("2014-10-01 18:00:00"), *o3 = "2014-10-01T18:00:00Z";

	ret = make_json_timestamp(i1);
	mu_assert(ret==o1,"converting timestamp into json timestamp failed");
	free(ret); free(i1);

	ret = make_json_timestamp(i2);
	mu_assert(!strcmp(ret,o2),"converting timestamp into json timestamp failed");
	free(ret); free(i2);

	ret = make_json_timestamp(i3);
	mu_assert(!strcmp(ret,o3),"converting timestamp into json timestamp failed");
	free(ret); free(i3);

	return NULL;
}

MU_TEST(test_get_command_id_by_key)
{
	int rc;
	opcode ret;
	char *i1 = strdup("listen"),
	*i2 = strdup("shutdown"),
	*i3 = strdup("lasten");
	opcode o1 = FT_LISTEN,
	o2 = CTRL_SHUTDOWN,
	o3 = 0;

	ret = 0;
	rc = get_command_id_by_key(i1, &ret);
	mu_assert(rc == 1 && ret==o1, "enconding command to key failed");
	free(i1);

	ret = 0;
	rc = get_command_id_by_key(i2, &ret);
	mu_assert(rc == 1 && ret==o2, "enconding command to key failed");
	free(i2);

	ret = 0;
	rc = get_command_id_by_key(i3, &ret);
	mu_assert(rc == 0 && ret==o3, "enconding command to key succeeded (but should've failed)");
	free(i3);

	return NULL;
}

MU_TEST_SUITE(test_suite)
{
	MU_RUN_TEST(test_get_arg_string);
	MU_RUN_TEST(test_make_json_timestamp);
	MU_RUN_TEST(test_get_command_id_by_key);
}

int main()
{
	MU_RUN_SUITE(test_suite);
	MU_REPORT();
	return 0;
}