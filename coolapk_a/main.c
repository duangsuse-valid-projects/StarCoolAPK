#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "include/coolapk.h"

// main tests
// bad practice
int main(int argc, const char **argv) {
    char *eb = malloc(100 * sizeof(char));
    char *db = malloc(100);
    char *meb = malloc(100);

    printf("BEL(100): %i\n", BEL(100));

    be(eb, "duangsuse");

    printf("be: %s\n", eb);

    bd(db, eb);

    printf("bd(be): %s\n", db);

    me(meb, "duangsuse");
    printf("me: %s\n", meb);

    r(meb);
    printf("r: %s\n", meb);
    r(db);
    printf("r: %s\n", db);

    // With a new soul
    char h[193] = "ldTM3cTZiFTMhFzMlFWN2cjMjVDNzQWYxYTOwU2MwIDZHljcadFN2wUe5omYyATdZJTO2J2RGdXY5VDdZhlSypFWRZXW6l1MadVWx8EVRpnT6dGMaRUQ14keVdnWH5UbZ1WS61EVBlXTHl1dZdVSvcDZzI2YmVWMjF2NwAjZkN2YmVTY4UTO1YWO4Y2NwQGO";   // [var_ddh]  // salted base64 // L73
    //char mt[];

    r(h); // reverse
    int h2_len = BDL(h); // L80

    char h2[h2_len];     // [var_190h] // decode output // L81

    bd(h2, h);

    printf("%s\n", h2);

    r(h2); // reverse

    printf("%s\n", h2);

    int n = strlen(h2) - 0x40;
    memcpy(h2, h2 + 0x20, n);

    printf("%s\n", h2);

    int h3_len = BDL(h2);
    char h3[h3_len];

    bd(h3, h2);
    printf("%s\n", h3);

    char t[128];

    int ti = (int) time(NULL);

    sprintf(t, "%d", ti);

    printf("t: %s\n", t);

    char ht[256];
    sprintf(ht, "%x", ti);

    printf("ht: %s\n", ht);

    char mt[256];
    me(mt, t);

    printf("me(t): %s\n", mt);

    char jstr[512];

    char packageNameChars[] = "com.coolapk.market";

    if (argc > 1) {
        strcpy(jstr, argv[1]);
    } else {
        strcpy(jstr, "b21f8496-4b35-45c7-8fff-49ac268f5a97");
    }

    char h4[strlen(h3) + strlen(jstr) + strlen(packageNameChars) + 256];
    strcat(h4, h3);
    strcat(h4, mt);

    strcat(h4, jstr);
    strcat(h4, packageNameChars);

    printf("h4: %s\n", h4);

    int rr_len = BEL(strlen(packageNameChars));
    char rr[rr_len + 1];

    be(rr, h4);
    printf("rr:(%i): %s\n", rr_len, rr);
    
    // 瞎 :chicken: 分配
    char fe[256];
    me(fe, rr);
    
    printf("fe: %s\n", fe);
    
    int fe_len = strlen(fe);
    int jstr_len = strlen(jstr);
    
    char fin[fe_len + jstr_len + rr_len + 1];
    strcat(fin, fe);
    strcat(fin, jstr);
    strcat(fin, ht);
    
    
    printf("fin: %s\n", fin);

    return 0;
}

