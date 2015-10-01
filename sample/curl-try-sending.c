#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <alloca.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <curl/curl.h>

const char* json_exmp_string = "{\"__PID\": \"1\", \"version\": \"1.1\", \"__BOOT_ID\": \"2d4466c33b7a4942b8ca11dcaeb4974c\", \"___MONOTONIC_TIMESTAMP\": 29376787359, \"__EXE\": \"/lib/systemd/systemd\", \"__CAP_EFFECTIVE\": \"3fffffffff\", \"___CURSOR\": \"s=86ee728ed8c6429383b58574aafb00c7;i=4ba6f;b=da9507f15a1c44e1a4d70f7c3195e0ef;m=6d6fe339f;t=51942c3121b7b;x=c3e393273245ef2e\", \"level\": 6, \"_SYSLOG_IDENTIFIER\": \"systemd\", \"host\": \"TPOSS\", \"short_message\": \"serial-getty@ttyS0.service has no holdoff time, scheduling restart.\", \"__TRANSPORT\": \"journal\", \"__HOSTNAME\": \"TPOSS\", \"_MESSAGE\": \"serial-getty@ttyS0.service has no holdoff time, scheduling restart.\", \"_CODE_LINE\": \"2541\", \"__UID\": \"0\", \"_SYSLOG_FACILITY\": \"3\", \"__MACHINE_ID\": \"9c18637da35643bd83793ff2b5a5a965\", \"__GID\": \"0\", \"__SOURCE_REALTIME_TIMESTAMP\": \"1435149414831862\", \"_PRIORITY\": \"6\", \"__CMDLINE\": \"/sbin/init\", \"_CODE_FILE\": \"/REDO/build/tmp/work/core2-64-tposs-linux/systemd/1_216+gitAUTOINC+5d0ae62c66-r0.5/git/src/core/service.c\", \"_CODE_FUNCTION\": \"service_dispatch_timer\", \"_UNIT\": \"serial-getty@ttyS0.service\", \"__COMM\": \"systemd\", \"__SYSTEMD_CGROUP\": \"/\"}";

int main (int argc, char *argv[]){
  CURL *curl;
  CURLcode res;

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.13.96:12201/gelf");
    /* specify to POST on the endpoint */
    curl_easy_setopt(curl, CURLOPT_POST, CURLOPT_POSTFIELDS);
    /* Now specify the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_exmp_string);


    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return 0;
}
