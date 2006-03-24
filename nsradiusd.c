/* 
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1(the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis,WITHOUT WARRANTY OF ANY KIND,either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively,the contents of this file may be used under the terms
 * of the GNU General Public License(the "GPL"),in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License,indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above,a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * Author Vlad Seryakov vlad@crystalballinc.com
 * 
 */

/*
 * nsradiusd.c -- RADIOUS module
 *
 *
 *  RADIUS requests
 *    ns_radius send host port secret ?Code code? ?Retries retries? ?Timeout timeout? ?attr value? ...
 *     performs RADIUS requests
 *
 *     Example:
 *       ns_radius send localhost 1645 secret User-Name test User-Password test2
 *
 * Authors
 *
 *     Vlad Seryakov vlad@crystalballinc.com
 */

#include "ns.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

// MD5 implementation
#define MD5_DIGEST_CHARS         16

#ifdef sun
#define HIGHFIRST
#endif

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x,  y,  z) (x & y | ~x & z) */
#define F1(x,  y,  z) (z ^ (x & (y ^ z)))
#define F2(x,  y,  z) F1(z,  x,  y)
#define F3(x,  y,  z) (x ^ y ^ z)
#define F4(x,  y,  z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f,  w,  x,  y,  z,  data,  s) \
	( w += f(x,  y,  z) + data,   w = w<<s | w>>(32-s),   w += x )

struct MD5Context {
    unsigned int buf[4];
    unsigned int bits[2];
    unsigned char in[64];
};
// To make happy RSA MD5 implementation
typedef struct MD5Context MD5_CTX;

// RADIUS ID definitions. See RFC 2138
#define RADIUS_ACCESS_REQUEST               1
#define RADIUS_ACCESS_ACCEPT                2
#define RADIUS_ACCESS_REJECT                3
#define RADIUS_ACCOUNTING_REQUEST           4
#define RADIUS_ACCOUNTING_RESPONSE          5
#define RADIUS_ACCOUNTING_STATUS            6
#define RADIUS_PASSWORD_REQUEST             7
#define RADIUS_PASSWORD_ACK                 8
#define RADIUS_PASSWORD_REJECT              9
#define RADIUS_ACCOUNTING_MESSAGE           10
#define RADIUS_ACCESS_CHALLENGE             11
#define RADIUS_STATUS_SERVER                12
#define RADIUS_STATUS_CLIENT                13

// RADIUS attribute definitions. Also from RFC 2138
#define RADIUS_USER_NAME                    1       /* string */
#define RADIUS_USER_PASSWORD                2       /* string */
#define RADIUS_CHAP_PASSWORD                3       /* string */
#define RADIUS_NAS_IP_ADDRESS               4       /* ipaddr */
#define RADIUS_NAS_PORT                     5       /* integer */
#define RADIUS_SERVICE_TYPE                 6       /* integer */
#define RADIUS_FRAMED_PROTOCOL              7       /* integer */
#define RADIUS_FRAMED_IP_ADDRESS            8       /* ipaddr */
#define RADIUS_FRAMED_IP_NETMASK            9       /* ipaddr */
#define RADIUS_FRAMED_ROUTING               10      /* integer */
#define RADIUS_FILTER_ID                    11      /* string */
#define RADIUS_FRAMED_MTU                   12      /* integer */
#define RADIUS_FRAMED_COMPRESSION           13      /* integer */
#define RADIUS_LOGIN_IP_HOST                14      /* ipaddr */
#define RADIUS_LOGIN_SERVICE                15      /* integer */
#define RADIUS_LOGIN_PORT                   16      /* integer */
#define RADIUS_OLD_PASSWORD                 17      /* string */
#define RADIUS_REPLY_MESSAGE                18      /* string */
#define RADIUS_LOGIN_CALLBACK_NUMBER        19      /* string */
#define RADIUS_FRAMED_CALLBACK_ID           20      /* string */
#define RADIUS_FRAMED_ROUTE                 22      /* string */
#define RADIUS_STATE                        24      /* string */
#define RADIUS_CLASS                        25      /* string */
#define RADIUS_VENDOR_SPECIFIC              26      /* string */
#define RADIUS_SESSION_TIMEOUT              27      /* integer */
#define RADIUS_IDLE_TIMEOUT                 28      /* integer */
#define RADIUS_TERMINATION_ACTION           29      /* integer */
#define RADIUS_CALLED_STATION_ID            30      /* string */
#define RADIUS_CALLING_STATION_ID           31      /* string */
#define RADIUS_NAS_IDENTIFIER               32      /* string */
#define RADIUS_PROXY_STATE                  33      /* string */
#define RADIUS_CHAP_CHALLENGE               60      /* string */
#define RADIUS_NAS_PORT_TYPE                61      /* integer */
#define RADIUS_PORT_LIMIT                   62      /* integer */
#define RADIUS_USER_ID                      99      /* string */

// Service types
#define RADIUS_LOGIN                  1
#define RADIUS_FRAMED                 2
#define RADIUS_CALLBACK_LOGIN         3
#define RADIUS_CALLBACK_FRAMED        4
#define RADIUS_OUTBOUND_USER          5
#define RADIUS_ADMINISTRATIVE_USER    6
#define RADIUS_SHELL_USER             7
#define RADIUS_AUTHENTICATE_ONLY      8
#define RADIUS_CALLBACK_ADMIN_USER    9

// Attribute types
#define RADIUS_TYPE_STRING            0
#define RADIUS_TYPE_INTEGER           1
#define RADIUS_TYPE_IPADDR            2
#define RADIUS_TYPE_DATE              3
#define RADIUS_TYPE_FILTER_BINARY     4

// RADIUS string limits
#define RADIUS_VECTOR_LEN             16
#define RADIUS_STRING_LEN             253
#define RADIUS_BUFFER_LEN             1524

// Default RADIUS ports
#define RADIUS_AUTH_PORT              1645
#define RADIUS_ACCT_PORT              1646

typedef unsigned char RadiusVector[RADIUS_VECTOR_LEN];

// Radius packet header
typedef struct _radiusHeader_t {
   unsigned char code;
   unsigned char id;
   unsigned short length;
   RadiusVector vector;
} RadiusHeader;

// Radius attribute
typedef struct _radiusAttr_t {
   struct _radiusAttr_t *next;
   short type;
   short vendor;
   short attribute;
   char name[RADIUS_STRING_LEN+1];
   unsigned char sval[RADIUS_STRING_LEN+1];
   unsigned int lval;
} RadiusAttr;

// Dictionary value
typedef struct _radiusValue_t {
   struct _radiusValue_t *next;
   char name[RADIUS_STRING_LEN+1];
   int value;
} RadiusValue;

// Dictionary attribute
typedef struct _radiusDict_t {
   struct _radiusDict_t *next;
   struct _radiusDict_t *prev;
   char name[RADIUS_STRING_LEN+1];
   int attribute;
   short vendor;
   short type;
   RadiusValue *values;
} RadiusDict;

// Client secret
typedef struct _radiusClient {
   struct _radiusClient *next;
   struct _radiusClient *prev;
   struct in_addr addr;
   char secret[RADIUS_VECTOR_LEN+1];
} RadiusClient;

// User record
typedef struct _radiusUser {
   RadiusAttr *config;
   RadiusAttr *reply;
} RadiusUser;

typedef struct _server {
   char *name;
   char *address;
   char *proc;
   int port;
   int sock;
   short errors;
   int drivermode;
   Ns_Mutex userMutex;
   Ns_Mutex clientMutex;
   Ns_Mutex requestMutex;
   Tcl_HashTable userList;
   RadiusClient *clientList;
   Ns_Mutex dictMutex;
   RadiusDict *dictList;
   struct sockaddr_in sa;
} Server;

typedef struct _radiusRequest {
   struct _radiusRequest *next,*prev;
   int sock;
   int req_id;
   int req_code;
   short req_length;
   short reply_length;
   int reply_code;
   char *buffer;
   int buffer_length;
   Server *server;
   RadiusAttr *req;
   RadiusAttr *reply;
   RadiusVector vector;
   RadiusClient *client;
   struct sockaddr_in sa;
} RadiusRequest;

static Ns_DriverProc RadiusProc;
static Ns_SockProc RadiusCallback;

static void RadiusInit(Server *server);
static int RadiusRequestReply(RadiusRequest *req);
static void RadiusRequestFree(RadiusRequest *req);
static void RadiusRequestProcess(RadiusRequest *req);
static RadiusRequest *RadiusRequestCreate(Server *server, SOCKET sock, char *buf, int len);
static int RadiusRequestProc(void *arg, Ns_Conn *conn);;
static int RadiusInterpInit(Tcl_Interp *interp, void *arg);
static int RadiusCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static RadiusAttr *RadiusAttrFind(RadiusAttr *vp, char *name, int attr, int vendor);

static void byteReverse(unsigned char *buf,  unsigned len);
static void MD5Transform(unsigned int buf[4],  unsigned int const in[16]);

static Ns_Tls radiusTls;

NS_EXPORT int Ns_ModuleVersion = 1;

/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *	Load the config parameters, setup the structures, and
 *	listen on the trap port.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Server will listen for SNMP traps on specified address and port.
 *
 *----------------------------------------------------------------------
 */

NS_EXPORT int Ns_ModuleInit(char *server, char *module)
{
    char *path;
    SOCKET sock;
    Server *srvPtr;
    Ns_DriverInitData init;
    static int initialized = 0;

    if (!initialized) {
        initialized = 1;
        Ns_TlsAlloc(&radiusTls, 0);
    }

    path = Ns_ConfigGetPath(server, module, NULL);
    srvPtr = (Server*)ns_calloc(1,sizeof(Server));
    srvPtr->name = server;
    Tcl_InitHashTable(&srvPtr->userList, TCL_STRING_KEYS);

    Ns_ConfigGetBool(path, "drivermode", &srvPtr->drivermode);
    srvPtr->address = Ns_ConfigGetValue(path, "address");
    srvPtr->proc = Ns_ConfigGetValue(path, "proc");
    srvPtr->port = Ns_ConfigIntRange(path, "port", RADIUS_AUTH_PORT, 1, 99999);
    if (Ns_GetSockAddr(&srvPtr->sa, srvPtr->address, 0) != NS_OK) {
        ns_free(srvPtr);
        return NS_ERROR;
    }
    /* Auth requests can be handled by callback or driver mode */
    if (srvPtr->proc != NULL && srvPtr->port > 0) {
        if (srvPtr->drivermode) {
            init.version = NS_DRIVER_VERSION_1;
            init.name = "nsradius";
            init.proc = RadiusProc;
            init.opts = NS_DRIVER_UDP;
            init.arg = srvPtr;
            init.path = NULL;
            if (Ns_DriverInit(server, module, &init) != NS_OK) {
                Ns_Log(Error, "nsradiusd: driver init failed.");
                ns_free(srvPtr);
                return NS_ERROR;
            }
            Ns_RegisterRequest(server, "RADIUS",  "/", RadiusRequestProc, NULL, srvPtr, 0);
        } else {
            if ((sock = Ns_SockListenUdp(srvPtr->address, srvPtr->port)) == -1) {
                Ns_Log(Error,"nsradiusd: couldn't create socket: %s:%d: %s", srvPtr->address, srvPtr->port, strerror(errno));
            } else {
                srvPtr->sock = sock;
                Ns_SockCallback(sock, RadiusCallback, srvPtr, NS_SOCK_READ|NS_SOCK_EXIT|NS_SOCK_EXCEPTION);
                Ns_Log(Notice,"nsradiusd: radius: listening on %s:%d by %s", srvPtr->address, srvPtr->port, srvPtr->proc);
            }
        }
    }
    RadiusInit(srvPtr);
    Ns_MutexSetName2(&srvPtr->dictMutex, "nsradiusd", "radiusDict");
    Ns_MutexSetName2(&srvPtr->userMutex, "nsradiusd", "radiusUser");
    Ns_MutexSetName2(&srvPtr->clientMutex, "nsradiusd", "radiusClient");
    Ns_MutexSetName2(&srvPtr->requestMutex, "nsradiusd", "radiusRequest");
    Ns_TclRegisterTrace(server, RadiusInterpInit, srvPtr, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusInterpInit --
 *
 *      Add ns_radius commands to interp.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
static int RadiusInterpInit(Tcl_Interp *interp, void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_radius", RadiusCmd, arg, NULL);
    return NS_OK;
}

static int RadiusProc(Ns_DriverCmd cmd, Ns_Sock *sock, struct iovec *bufs, int nbufs)
{
    Ns_DString *ds;
    RadiusRequest *req;
    Server *server = sock->driver->arg;

    switch (cmd) {
     case DriverAccept:
         /*
          * Read the packet and store it in the request buffer, registered proc
          * then will use that data for processing
          */

         if (Ns_DriverSockRequest(sock, "RADIUS / RADIUS/1.0") == NS_OK) {
             ds = Ns_DriverSockContent(sock);
             Tcl_DStringSetLength(ds, sock->driver->bufsize);
             req = RadiusRequestCreate(server, sock->sock, ds->string, ds->length);
             if (req != NULL) {
                 /* Adjust buffer to actual read size */
                 ds->length = req->req_length;
                 sock->sa = req->sa;
                 sock->arg = req;
                 return NS_OK;
             }
         }
         break;

     case DriverRecv:
     case DriverSend:
     case DriverClose:
     case DriverKeep:
         break;
    }
    return NS_ERROR;
}

static int RadiusRequestProc(void *arg, Ns_Conn *conn)
{
    char buf[282];
    RadiusAttr *attr;
    Ns_Sock *sock = Ns_ConnSockPtr(conn);
    RadiusRequest *req = (RadiusRequest*)sock->arg;

    if (req != NULL) {
        Ns_ConnSetPeer(conn, &req->sa);
        RadiusRequestProcess(req);
        /* For access log file */
        attr = RadiusAttrFind(req->req, NULL, RADIUS_USER_NAME, 0);
        if (attr) {
            ns_free(conn->request->line);
            snprintf(buf, sizeof(buf), "GET /%s RADIUS/1.0", attr->sval);
            conn->request->line = ns_strdup(buf);
            Ns_ConnSetContentSent(conn, req->reply_length);
            Ns_ConnSetResponseStatus(conn, req->reply_code);
        }
    } else {
        Ns_Log(Error, "Radius: FD %d: %s: invalid connection", req->sock, ns_inet_ntoa(sock->sa.sin_addr));
    }
    RadiusRequestFree(req);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusProc --
 *
 *	Socket callback to receive RADIUS requests
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	New RadiusThread will be created.
 *
 *----------------------------------------------------------------------
 */

static int RadiusCallback(SOCKET sock, void *arg, int when)
{
    RadiusRequest *req;
    char buf[RADIUS_BUFFER_LEN];
    Server *server = (Server*)arg;

    switch(when) {
     case NS_SOCK_READ:
         req = RadiusRequestCreate(server, sock, buf, sizeof(buf));
         if (req) {
             RadiusRequestProcess(req);
             RadiusRequestFree(req);
         }
         return NS_TRUE;
    }
    close(sock);
    return NS_FALSE;
}

/*
 * Note: this code is harmless on little-endian machines.
 */
static void byteReverse(unsigned char *buf,  unsigned len)
{
#ifdef HIGHFIRST
    unsigned int t;
    do {
      t = (unsigned int) ((unsigned) buf[3] << 8 | buf[2]) << 16 | ((unsigned) buf[1] << 8 | buf[0]);
      *(unsigned int *) buf = t;
      buf += 4;
    } while (--len);
#endif
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static void MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301U;
    ctx->buf[1] = 0xefcdab89U;
    ctx->buf[2] = 0x98badcfeU;
    ctx->buf[3] = 0x10325476U;
    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void MD5Update(struct MD5Context *ctx,  unsigned const char *buf,  unsigned len)
{
    unsigned int t;

    /* Update bitcount */
    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((unsigned int) len << 3)) < t) ctx->bits[1]++;
    ctx->bits[1] += len >> 29;
    t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */
    /* Handle any leading odd-sized chunks */
    if (t) {
	unsigned char *p = (unsigned char *) ctx->in + t;
	t = 64 - t;
	if (len < t) {
	  memcpy(p,  buf,  len);
          return;
	}
	memcpy(p,  buf,  t);
	byteReverse(ctx->in,  16);
	MD5Transform(ctx->buf,  (unsigned int *) ctx->in);
	buf += t;
	len -= t;
    }
    /* Process data in 64-byte chunks */
    while (len >= 64) {
        memcpy(ctx->in,  buf,  64);
        byteReverse(ctx->in,  16);
        MD5Transform(ctx->buf,  (unsigned int *) ctx->in);
        buf += 64;
        len -= 64;
    }
    /* Handle any remaining bytes of data. */
    memcpy(ctx->in,  buf,  len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed,  MSB-first)
 */
static void MD5Final(unsigned char digest[16],  struct MD5Context *ctx)
{
    unsigned count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;
    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;
    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;
    /* Pad out to 56 mod 64 */
    if (count < 8) {
        /* Two lots of padding:  Pad the first block to 64 bytes */
        memset(p,  0,  count);
        byteReverse(ctx->in,  16);
        MD5Transform(ctx->buf,  (unsigned int *) ctx->in);
        /* Now fill the next block with 56 bytes */
        memset(ctx->in,  0,  56);
    } else {
        /* Pad block to 56 bytes */
        memset(p,  0,  count - 8);
    }
    byteReverse(ctx->in,  14);
    /* Append length in bits and transform */
    ((unsigned int *) ctx->in)[14] = ctx->bits[0];
    ((unsigned int *) ctx->in)[15] = ctx->bits[1];
    MD5Transform(ctx->buf,  (unsigned int *) ctx->in);
    byteReverse((unsigned char *) ctx->buf,  4);
    memcpy(digest,  ctx->buf,  16);
    memset(ctx,  0,  sizeof(ctx));	/* In case it's sensitive */
}

/*
 * The core of the MD5 algorithm,  this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void MD5Transform(unsigned int buf[4],  unsigned int const in[16])
{
    register unsigned int a,  b,  c,  d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1,  a,  b,  c,  d,   in[0] + 0xd76aa478U,   7);
    MD5STEP(F1,  d,  a,  b,  c,   in[1] + 0xe8c7b756U,  12);
    MD5STEP(F1,  c,  d,  a,  b,   in[2] + 0x242070dbU,  17);
    MD5STEP(F1,  b,  c,  d,  a,   in[3] + 0xc1bdceeeU,  22);
    MD5STEP(F1,  a,  b,  c,  d,   in[4] + 0xf57c0fafU,   7);
    MD5STEP(F1,  d,  a,  b,  c,   in[5] + 0x4787c62aU,  12);
    MD5STEP(F1,  c,  d,  a,  b,   in[6] + 0xa8304613U,  17);
    MD5STEP(F1,  b,  c,  d,  a,   in[7] + 0xfd469501U,  22);
    MD5STEP(F1,  a,  b,  c,  d,   in[8] + 0x698098d8U,   7);
    MD5STEP(F1,  d,  a,  b,  c,   in[9] + 0x8b44f7afU,  12);
    MD5STEP(F1,  c,  d,  a,  b,  in[10] + 0xffff5bb1U,  17);
    MD5STEP(F1,  b,  c,  d,  a,  in[11] + 0x895cd7beU,  22);
    MD5STEP(F1,  a,  b,  c,  d,  in[12] + 0x6b901122U,   7);
    MD5STEP(F1,  d,  a,  b,  c,  in[13] + 0xfd987193U,  12);
    MD5STEP(F1,  c,  d,  a,  b,  in[14] + 0xa679438eU,  17);
    MD5STEP(F1,  b,  c,  d,  a,  in[15] + 0x49b40821U,  22);

    MD5STEP(F2,  a,  b,  c,  d,   in[1] + 0xf61e2562U,   5);
    MD5STEP(F2,  d,  a,  b,  c,   in[6] + 0xc040b340U,   9);
    MD5STEP(F2,  c,  d,  a,  b,  in[11] + 0x265e5a51U,  14);
    MD5STEP(F2,  b,  c,  d,  a,   in[0] + 0xe9b6c7aaU,  20);
    MD5STEP(F2,  a,  b,  c,  d,   in[5] + 0xd62f105dU,   5);
    MD5STEP(F2,  d,  a,  b,  c,  in[10] + 0x02441453U,   9);
    MD5STEP(F2,  c,  d,  a,  b,  in[15] + 0xd8a1e681U,  14);
    MD5STEP(F2,  b,  c,  d,  a,   in[4] + 0xe7d3fbc8U,  20);
    MD5STEP(F2,  a,  b,  c,  d,   in[9] + 0x21e1cde6U,   5);
    MD5STEP(F2,  d,  a,  b,  c,  in[14] + 0xc33707d6U,   9);
    MD5STEP(F2,  c,  d,  a,  b,   in[3] + 0xf4d50d87U,  14);
    MD5STEP(F2,  b,  c,  d,  a,   in[8] + 0x455a14edU,  20);
    MD5STEP(F2,  a,  b,  c,  d,  in[13] + 0xa9e3e905U,   5);
    MD5STEP(F2,  d,  a,  b,  c,   in[2] + 0xfcefa3f8U,   9);
    MD5STEP(F2,  c,  d,  a,  b,   in[7] + 0x676f02d9U,  14);
    MD5STEP(F2,  b,  c,  d,  a,  in[12] + 0x8d2a4c8aU,  20);

    MD5STEP(F3,  a,  b,  c,  d,   in[5] + 0xfffa3942U,   4);
    MD5STEP(F3,  d,  a,  b,  c,   in[8] + 0x8771f681U,  11);
    MD5STEP(F3,  c,  d,  a,  b,  in[11] + 0x6d9d6122U,  16);
    MD5STEP(F3,  b,  c,  d,  a,  in[14] + 0xfde5380cU,  23);
    MD5STEP(F3,  a,  b,  c,  d,   in[1] + 0xa4beea44U,   4);
    MD5STEP(F3,  d,  a,  b,  c,   in[4] + 0x4bdecfa9U,  11);
    MD5STEP(F3,  c,  d,  a,  b,   in[7] + 0xf6bb4b60U,  16);
    MD5STEP(F3,  b,  c,  d,  a,  in[10] + 0xbebfbc70U,  23);
    MD5STEP(F3,  a,  b,  c,  d,  in[13] + 0x289b7ec6U,   4);
    MD5STEP(F3,  d,  a,  b,  c,   in[0] + 0xeaa127faU,  11);
    MD5STEP(F3,  c,  d,  a,  b,   in[3] + 0xd4ef3085U,  16);
    MD5STEP(F3,  b,  c,  d,  a,   in[6] + 0x04881d05U,  23);
    MD5STEP(F3,  a,  b,  c,  d,   in[9] + 0xd9d4d039U,   4);
    MD5STEP(F3,  d,  a,  b,  c,  in[12] + 0xe6db99e5U,  11);
    MD5STEP(F3,  c,  d,  a,  b,  in[15] + 0x1fa27cf8U,  16);
    MD5STEP(F3,  b,  c,  d,  a,   in[2] + 0xc4ac5665U,  23);

    MD5STEP(F4,  a,  b,  c,  d,   in[0] + 0xf4292244U,   6);
    MD5STEP(F4,  d,  a,  b,  c,   in[7] + 0x432aff97U,  10);
    MD5STEP(F4,  c,  d,  a,  b,  in[14] + 0xab9423a7U,  15);
    MD5STEP(F4,  b,  c,  d,  a,   in[5] + 0xfc93a039U,  21);
    MD5STEP(F4,  a,  b,  c,  d,  in[12] + 0x655b59c3U,   6);
    MD5STEP(F4,  d,  a,  b,  c,   in[3] + 0x8f0ccc92U,  10);
    MD5STEP(F4,  c,  d,  a,  b,  in[10] + 0xffeff47dU,  15);
    MD5STEP(F4,  b,  c,  d,  a,   in[1] + 0x85845dd1U,  21);
    MD5STEP(F4,  a,  b,  c,  d,   in[8] + 0x6fa87e4fU,   6);
    MD5STEP(F4,  d,  a,  b,  c,  in[15] + 0xfe2ce6e0U,  10);
    MD5STEP(F4,  c,  d,  a,  b,   in[6] + 0xa3014314U,  15);
    MD5STEP(F4,  b,  c,  d,  a,  in[13] + 0x4e0811a1U,  21);
    MD5STEP(F4,  a,  b,  c,  d,   in[4] + 0xf7537e82U,   6);
    MD5STEP(F4,  d,  a,  b,  c,  in[11] + 0xbd3af235U,  10);
    MD5STEP(F4,  c,  d,  a,  b,   in[2] + 0x2ad7d2bbU,  15);
    MD5STEP(F4,  b,  c,  d,  a,   in[9] + 0xeb86d391U,  21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

static void MD5Calc(unsigned char *output,  unsigned char *input,  unsigned int inlen)
{
    MD5_CTX context;

    MD5Init(&context);
    MD5Update(&context,  input,  inlen);
    MD5Final(output,  &context);
}

static RadiusDict *RadiusDictFind(Server *server, char *name, int attr, int vendor, int unlink)
{
    RadiusDict *dict;

    if (attr == -1 && name) {
        attr = atoi(name);
    }
    Ns_MutexLock(&server->dictMutex);
    for (dict = server->dictList; dict; dict = dict->next) {
        if (vendor == -1 || dict->vendor == vendor) {
            if (dict->attribute == attr || (name && !strcasecmp(dict->name, name))) {
                break;
            }
        }
    }
    if (unlink && dict) {
        if (dict->prev) {
            dict->prev->next = dict->next;
        }
        if (dict->next) {
            dict->next->prev = dict->prev;
        }
        if (dict == server->dictList) {
            server->dictList = dict->next;
        }
        dict->next = dict->prev = 0;
    }
    Ns_MutexUnlock(&server->dictMutex);
    return dict;
}

static RadiusDict *RadiusDictAdd(Server *server, char *name, int attr, int vendor, int type)
{
    RadiusDict *dict = 0;

    if (attr && name) {
        dict = (RadiusDict*)ns_calloc(1, sizeof(RadiusDict));
        dict->type = type;
        dict->vendor = vendor;
        dict->attribute = attr;
        strncpy(dict->name, name, RADIUS_STRING_LEN);
        Ns_StrToLower(dict->name);
        Ns_MutexLock(&server->dictMutex);
        dict->next = server->dictList;
        if (dict->next) {
            dict->next->prev = dict;
        }
        server->dictList = dict;
        Ns_MutexUnlock(&server->dictMutex);
    }
    return dict;
}

static void RadiusDictPrintf(Server *server, Ns_DString *ds)
{
    RadiusDict *dict;
    RadiusValue *value;

    Ns_MutexLock(&server->dictMutex);
    for (dict = server->dictList; dict; dict = dict->next) {
        Ns_DStringPrintf(ds, "%s %d %d %d {", dict->name, dict->attribute, dict->vendor, dict->type);
        for (value = dict->values; value; value = value->next) {
            Ns_DStringPrintf(ds, "%s %d ", value->name, value->value);
        }
        Ns_DStringPrintf(ds, "} ");
    }
    Ns_MutexUnlock(&server->dictMutex);
}

// generate a random vector
static void RadiusVectorCreate(RadiusVector vector)
{
    MD5_CTX md5;
    struct timeval tv;
    struct timezone tz;

    // Use the time of day with the best resolution the system can
    // give us -- often close to microsecond accuracy.
    gettimeofday(&tv, &tz);
    tv.tv_sec ^= getpid() * Ns_ThreadId(); /* add some secret information */
    // Hash things to get some cryptographically strong pseudo-random numbers
    MD5Init(&md5);
    MD5Update(&md5, (unsigned char *)&tv, sizeof(tv));
    MD5Update(&md5, (unsigned char *)&tz, sizeof(tz));
    MD5Final(vector, &md5);
}

// MD5(packet header + packet data + secret)
static int RadiusVectorVerify(RadiusHeader *hdr, RadiusVector vector, char *secret)
{
    MD5_CTX md5;
    RadiusVector digest, reply;

    memcpy(reply, hdr->vector, RADIUS_VECTOR_LEN);
    memcpy(hdr->vector, vector, RADIUS_VECTOR_LEN);
    MD5Init(&md5);
    MD5Update(&md5, (unsigned char *)hdr, ntohs(hdr->length));
    MD5Update(&md5, (unsigned char *)secret, strlen(secret));
    MD5Final(digest, &md5);
    return memcmp(digest, reply, RADIUS_VECTOR_LEN);
}

static void RadiusPasswdDecrypt(RadiusAttr *attr, RadiusVector vector, char *secret, char *salt, int saltlen)
{
    RadiusVector digest;
    unsigned char *p = vector;
    unsigned char pw[RADIUS_STRING_LEN+1];
    unsigned char md5[RADIUS_STRING_LEN+1];
    unsigned int i, j, secretlen = strlen(secret);

    memset(pw, 0, RADIUS_STRING_LEN+1);
    memcpy(pw, attr->sval, attr->lval);
    memcpy(md5, secret, secretlen);
    for (i = 0;i < attr->lval;) {
        memcpy(&md5[secretlen], p, RADIUS_VECTOR_LEN);
        if (!i && saltlen) {
            memcpy(&md5[secretlen + RADIUS_VECTOR_LEN], salt, saltlen);
            MD5Calc(digest, md5, secretlen + RADIUS_VECTOR_LEN + saltlen);
        } else {
            MD5Calc(digest, md5, secretlen + RADIUS_VECTOR_LEN);
        }
        p = &attr->sval[i];
        for (j = 0;j < RADIUS_VECTOR_LEN;j++, i++) pw[i] ^= digest[j];
    }
    attr->lval = strlen((char*)pw);
    memcpy(attr->sval, pw, RADIUS_STRING_LEN);
}

static void RadiusPasswdEncrypt(RadiusAttr *attr, RadiusVector vector, char *secret, char *salt, int saltlen)
{
    RadiusVector digest;
    unsigned int chunks;
    unsigned char *p = vector;
    unsigned char pw[RADIUS_STRING_LEN+1];
    unsigned char md5[RADIUS_STRING_LEN+1];
    unsigned int i, j, secretlen = strlen(secret);

    memset(pw, 0, RADIUS_STRING_LEN+1);
    memcpy(pw, attr->sval, attr->lval);
    memcpy(md5, secret, secretlen);
    chunks = (attr->lval + RADIUS_VECTOR_LEN - 1) / RADIUS_VECTOR_LEN;
    for (i = 0;i < chunks * RADIUS_VECTOR_LEN; ) {
        memcpy(&md5[secretlen], p, RADIUS_VECTOR_LEN);
        if (i == 0 && saltlen) {
            memcpy(&md5[secretlen + RADIUS_VECTOR_LEN], salt, saltlen);
            MD5Calc(digest, md5,  secretlen + RADIUS_VECTOR_LEN + saltlen);
        } else {
            MD5Calc(digest, md5, secretlen + RADIUS_VECTOR_LEN);
        }
        p = &pw[i];
        for (j = 0; j < RADIUS_VECTOR_LEN; j++,  i++) {
            pw[i] ^= digest[j];
        }
    }
    attr->lval = chunks * RADIUS_VECTOR_LEN;
    memcpy(attr->sval, pw, RADIUS_STRING_LEN);
}

static RadiusAttr *RadiusAttrCreate(Server *server, char *name, int attr, int vendor, char *val, int len)
{
    RadiusAttr *vp;
    RadiusDict *dict;
    RadiusValue *value;

    dict = RadiusDictFind(server, name, attr, vendor, 0);
    if (!dict && attr <= 0) {
        Ns_Log(Error, "RadiusAttrCreate: unknown attr: %s %d %d", name, attr, vendor);
        return 0;
    }
    vp = (RadiusAttr*)ns_calloc(1, sizeof(RadiusAttr));
    vp->attribute = attr;
    if (dict) {
        vp->type = dict->type;
        vp->vendor = dict->vendor;
        vp->attribute = dict->attribute;
        strcpy(vp->name, dict->name);
    } else {
        sprintf(vp->name, "A%d-V%d", attr, vendor);
        vp->type = RADIUS_TYPE_STRING;
    }
    switch(vp->type) {
     case RADIUS_TYPE_STRING:
         if (len <= 0) {
             len = strlen((const char*)val);
         }
         vp->lval = len < RADIUS_STRING_LEN ? len : RADIUS_STRING_LEN;
         memcpy(vp->sval, val, vp->lval);
         Ns_StrTrimRight((char*)vp->sval);
         break;
     case RADIUS_TYPE_FILTER_BINARY:
         if (len <= 0) {
             len = strlen((const char*)val);
         }
         vp->lval = len < RADIUS_STRING_LEN ? len : RADIUS_STRING_LEN;
         memcpy(vp->sval, val, vp->lval);
         break;
     case RADIUS_TYPE_INTEGER:
         // Try values for that attribute
         if (isalpha(val[0])) {
             for (value = dict->values;  value; value = value->next) {
                 if (!strcasecmp(value->name, val)) {
                     vp->lval = value->value;
                     return vp;
                 }
             }
         }
     case RADIUS_TYPE_DATE:
     case RADIUS_TYPE_IPADDR:
         if (len > 0) {
             vp->lval = ntohl(*(unsigned long *)val);
         } else
         if (len < 0) {
             vp->lval = atol((const char*)val);
         } else {
             memcpy(&vp->lval, val, sizeof(vp->lval));
         }
         break;
     default:
         ns_free(vp);
         vp = 0;
    }
    return vp;
}

static void RadiusAttrPrintf(RadiusAttr *vp, Ns_DString *ds, int printname, int printall)
{
    unsigned i;
    char buf[64];
    RadiusAttr *attr;

    for (attr = vp; attr; attr = attr->next) {
        if (attr != vp) {
            Ns_DStringAppend(ds, " ");
        }
        if (printname) {
            Ns_DStringPrintf(ds, "%s ", attr->name);
        }
        switch(attr->type) {
         case RADIUS_TYPE_DATE:
            strftime(buf, sizeof(buf), "%Y-%m-%d %T", ns_localtime((const time_t*)&attr->lval));
            Ns_DStringPrintf(ds, "%s%s%s", printname?"{":"", buf, printname?"}":"");
            break;
         case RADIUS_TYPE_INTEGER:
            Ns_DStringPrintf(ds, "%d", attr->lval);
            break;
         case RADIUS_TYPE_IPADDR:
            Ns_DStringPrintf(ds, "%s", ns_inet_ntoa(*((struct in_addr*)&attr->lval)));
            break;
         case RADIUS_TYPE_STRING:
         case RADIUS_TYPE_FILTER_BINARY:
            for (i = 0; i < attr->lval; i++) {
                 if (!isprint((int)attr->sval[i])) {
                     break;
                 }
            }
            if (i == attr->lval) {
                Ns_DStringPrintf(ds, "%s%s%s", printname?"{":"", attr->sval, printname?"}":"");
                break;
            }
         default:
            for (i = 0; i < attr->lval; i++) {
                Ns_DStringPrintf(ds, "%2.2X", attr->sval[i]);
            }
        }
        if (!printall) {
            break;
        }
      }
}

static void RadiusAttrLink(RadiusAttr **list, RadiusAttr *vp)
{
    for (;*list; list = &(*list)->next);
    *list = vp;
}

static RadiusAttr *RadiusAttrFind(RadiusAttr *vp, char *name, int attr, int vendor)
{
    for (;vp; vp = vp->next) {
        if (vendor == -1 || vp->vendor == vendor) {
            if (vp->attribute == attr || (name && !strcasecmp(vp->name, name))) {
                return vp;
            }
        }
    }
    return 0;
}

static void RadiusAttrFree(RadiusAttr **vp)
{
    while (*vp) {
        RadiusAttr *next = (*vp)->next;
        ns_free(*vp);
        *vp = next;
    }
}

static RadiusAttr *RadiusAttrParse(Server *server, RadiusHeader *auth, int len, char *secret)
{
    RadiusAttr *head = 0, *vp;
    int length, vendor, attr, attrlen;
    unsigned char *ptr, *p0 = (unsigned char*)auth;

    // Extract attribute-value pairs
    ptr = p0 + sizeof(RadiusHeader);
    length = ntohs(auth->length) - sizeof(RadiusHeader);
    while (length > 0) {
        if ((ptr - p0) + 2 >= RADIUS_BUFFER_LEN) {
            break;
        }
        vendor = 0;
        attr = *ptr++;
        attrlen = *ptr++;
        attrlen -= 2;
        if (attrlen < 0 ||
            attrlen > RADIUS_STRING_LEN ||
            (ptr - p0) + attrlen >= RADIUS_BUFFER_LEN) {
            break;
        }
        // Vendor specific attribute
        if (attr == RADIUS_VENDOR_SPECIFIC) {
            if (((ptr - p0)) + attrlen + 6 >= RADIUS_BUFFER_LEN) {
                break;
            }
            memcpy(&vendor, ptr, 4);
            vendor = ntohl(vendor);
            ptr += 4;
            attr = *ptr++;
            ptr++;
            attrlen -= 6;
            length -= 6;
        }
        if ((vp = RadiusAttrCreate(server, 0, attr, vendor, (char*)ptr, attrlen))) {
            RadiusAttrLink(&head, vp);
            /* Perform decryption if necessary */
            switch(vp->attribute) {
             case RADIUS_USER_PASSWORD:
                RadiusPasswdDecrypt(vp, auth->vector, secret, 0, 0);
                break;
            }
        }
        ptr += attrlen;
        length -= attrlen + 2;
    }
    return head;
}

static unsigned char *RadiusAttrPack(RadiusAttr *vp, unsigned char *ptr, short *length)
{
    unsigned char *p0 = ptr, *vptr;
    unsigned int lvalue, len, vlen = 0;

    if (!ptr || !vp) {
        return ptr;
    }
    if (vp->vendor > 0) {
        vlen = 6;
        if (*length + vlen >= RADIUS_BUFFER_LEN) {
            return p0;
        }
        *ptr++ = RADIUS_VENDOR_SPECIFIC;
        /* Remember length position */
        p0 = ptr;
        /* Length of VS header (len/opt/oid) */
        *ptr++ = 6;
        lvalue = htonl(vp->vendor);
        memcpy(ptr,  &lvalue,  4);
        ptr += 4;
        *length += 6;
    }
    switch (vp->type) {
     case RADIUS_TYPE_STRING:
         len = strlen((char*)vp->sval);
         vptr = vp->sval;
         break;
     case RADIUS_TYPE_FILTER_BINARY:
         len = vp->lval;
         vptr = vp->sval;
         break;
     case RADIUS_TYPE_DATE:
     case RADIUS_TYPE_IPADDR:
     case RADIUS_TYPE_INTEGER:
         len = sizeof(lvalue);
         lvalue = htonl(vp->lval);
         vptr = (unsigned char*)&lvalue;
         break;
     default:
         return p0;
    }
    if (*length + len + 2 >= RADIUS_BUFFER_LEN) {
        return p0;
    }
    /* Store the attribute and value */
    *ptr++ = vp->attribute;
    *ptr++ = len + 2;
    memcpy(ptr, vptr, len);
    ptr += len;
    *length += len + 2;
    if (vp->vendor > 0) {
        *p0 += len + 2;
    }
    return ptr;
}

static int RadiusHeaderPack(RadiusHeader *hdr, int id, int code, RadiusVector vector, RadiusAttr *vp, char *secret)
{
    MD5_CTX md5;
    unsigned char *ptr;
    RadiusVector digest;

    if (!hdr || !secret || !vector) {
        return 0;
    }
    // Generate random id
    if (!id) {
        srand(time(0) ^ getpid());
        id = (rand() ^ (int)hdr);
    }
    hdr->id = id;
    hdr->code = code;
    hdr->length = sizeof(RadiusHeader);
    ptr = ((unsigned char*)hdr) + hdr->length;
    memcpy(hdr->vector, vector, RADIUS_VECTOR_LEN);
    // Pack attributes into the packet
    for (;vp; vp = vp->next) {
        switch(vp->attribute) {
         case RADIUS_USER_PASSWORD:
            RadiusPasswdEncrypt(vp, hdr->vector, secret, 0, 0);
            break;
        }
        ptr = RadiusAttrPack(vp, ptr, (short*)&hdr->length);
    }
    hdr->length = htons(hdr->length);
    // Finish packing
    switch(code) {
     case RADIUS_ACCESS_REQUEST:
     case RADIUS_STATUS_SERVER:
        break;

     case RADIUS_ACCOUNTING_REQUEST:
        /* Calculate the md5 hash over the entire packet and put it in the vector. */
        memset(hdr->vector, 0, RADIUS_VECTOR_LEN);
        MD5Init(&md5);
        MD5Update(&md5, (unsigned char *)hdr, ntohs(hdr->length));
        MD5Update(&md5, (unsigned char *)secret, strlen(secret));
        MD5Final(digest, &md5);
        memcpy(hdr->vector, vector, RADIUS_VECTOR_LEN);
        break;

     case RADIUS_ACCESS_ACCEPT:
     case RADIUS_ACCESS_REJECT:
     case RADIUS_ACCOUNTING_RESPONSE:
     case RADIUS_ACCESS_CHALLENGE:
        MD5Init(&md5);
        MD5Update(&md5, (unsigned char *)hdr, ntohs(hdr->length));
        MD5Update(&md5, (unsigned char *)secret, strlen(secret));
        MD5Final(digest, &md5);
        memcpy(hdr->vector, digest, RADIUS_VECTOR_LEN);
        break;

     default:
        /* Calculate the response digest and store it in the vector */
        memset(hdr->vector, 0, RADIUS_VECTOR_LEN);
        MD5Init(&md5);
        MD5Update(&md5, (unsigned char *)hdr, ntohs(hdr->length));
        MD5Update(&md5, (unsigned char *)secret, strlen(secret));
        MD5Final(digest, &md5);
        memcpy(hdr->vector, digest, RADIUS_VECTOR_LEN);
        break;
    }
    return ntohs(hdr->length);
}

static void RadiusClientAdd(Server *server, char *host, char *secret)
{
    RadiusClient *client;
    struct sockaddr_in addr;

    if (Ns_GetSockAddr(&addr, host, 0) != NS_OK) {
        return;
    }
    client = (RadiusClient*)ns_calloc(1, sizeof(RadiusClient));
    client->addr = addr.sin_addr;
    strncpy(client->secret, secret, RADIUS_VECTOR_LEN);
    Ns_MutexLock(&server->clientMutex);
    client->next = server->clientList;
    if (client->next) {
        client->next->prev = client;
    }
    server->clientList = client;
    Ns_MutexUnlock(&server->clientMutex);
}

static void RadiusClientPrintf(Server *server, Ns_DString *ds)
{
    RadiusClient *client;

    Ns_MutexLock(&server->clientMutex);
    for (client = server->clientList; client; client = client->next) {
        Ns_DStringPrintf(ds, "%s %s ", ns_inet_ntoa(client->addr), client->secret);
    }
    Ns_MutexUnlock(&server->clientMutex);
}

static RadiusClient *RadiusClientFind(Server *server, struct in_addr addr, int unlink)
{
    RadiusClient *client = 0;

    Ns_MutexLock(&server->clientMutex);
    for (client = server->clientList; client; client = client->next) {
        if (!memcmp(&client->addr, &addr, sizeof(struct in_addr))) {
            break;
        }
    }
    if (unlink && client) {
        if (client->prev) {
            client->prev->next = client->next;
        }
        if (client->next) {
            client->next->prev = client->prev;
        }
        if (client == server->clientList) {
            server->clientList = client->next;
        }
        client->next = client->prev = 0;
    }
    Ns_MutexUnlock(&server->clientMutex);
    return client;
}

static RadiusUser *RadiusUserAdd(Server *server, char *user)
{
    int n;
    RadiusUser *rec;
    Tcl_HashEntry *entry;

    Ns_MutexLock(&server->userMutex);
    entry = Tcl_CreateHashEntry(&server->userList, user, &n);
    if (n) {
        rec = (RadiusUser*)ns_calloc(1, sizeof(RadiusUser));
        Tcl_SetHashValue(entry, (ClientData)rec);
    }
    rec = (RadiusUser*)Tcl_GetHashValue(entry);
    Ns_MutexUnlock(&server->userMutex);
    return rec;
}

static void RadiusUserDel(Server *server, char *user)
{
    Tcl_HashEntry *entry;
    Tcl_HashSearch search;

    Ns_MutexLock(&server->userMutex);
    entry = Tcl_FirstHashEntry(&server->userList, &search);
    while (entry) {
      if (!user || Tcl_StringCaseMatch(Tcl_GetHashKey(&server->userList, entry), user, 1)) {
          ns_free(Tcl_GetHashValue(entry));
          Tcl_DeleteHashEntry(entry);
      }
      entry = Tcl_NextHashEntry(&search);
    }
    Ns_MutexUnlock(&server->userMutex);
}

static RadiusUser *RadiusUserFind(Server *server, char *user, Ns_DString *ds)
{
    RadiusUser *rec = 0;
    Tcl_HashEntry *entry;

    Ns_MutexLock(&server->userMutex);
    entry = Tcl_FindHashEntry(&server->userList, user);
    if (entry) {
        rec = (RadiusUser*)Tcl_GetHashValue(entry);
        Ns_DStringAppend(ds, "{");
        RadiusAttrPrintf(rec->config, ds, 1, 1);
        Ns_DStringAppend(ds, "} {");
        RadiusAttrPrintf(rec->reply, ds, 1, 1);
        Ns_DStringAppend(ds, "} ");
    }
    Ns_MutexUnlock(&server->userMutex);
    return rec;
}

static int RadiusUserAttrFind(Server *server, char *user, Ns_DString *ds, char *name, int reply)
{
    int rc = 0;
    RadiusUser *rec;
    RadiusAttr *attr;
    Tcl_HashEntry *entry;

    Ns_MutexLock(&server->userMutex);
    entry = Tcl_FindHashEntry(&server->userList, user);
    if (entry) {
        rec = (RadiusUser*)Tcl_GetHashValue(entry);
        attr = RadiusAttrFind(reply ? rec->reply : rec->config, name, -1, -1);
        if (attr) {
            RadiusAttrPrintf(attr, ds, 0, 0);
            rc = 1;
        }
    }
    Ns_MutexUnlock(&server->userMutex);
    return rc;
}

static void RadiusUserList(Server *server, char *user, Ns_DString *ds)
{
    RadiusUser *rec;
    Tcl_HashEntry *entry;
    Tcl_HashSearch search;

    Ns_MutexLock(&server->userMutex);
    entry = Tcl_FirstHashEntry(&server->userList, &search);
    while (entry) {
      if (!user || Tcl_StringCaseMatch(Tcl_GetHashKey(&server->userList, entry), user, 1)) {
          rec = (RadiusUser*)Tcl_GetHashValue(entry);
          Ns_DStringPrintf(ds, "%s {", Tcl_GetHashKey(&server->userList, entry));
          RadiusAttrPrintf(rec->config, ds, 1, 1);
          Ns_DStringAppend(ds, "} {");
          RadiusAttrPrintf(rec->reply, ds, 1, 1);
          Ns_DStringAppend(ds, "} ");
      }
      entry = Tcl_NextHashEntry(&search);
    }
    Ns_MutexUnlock(&server->userMutex);
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusCmd --
 *
 *	Send RADIUS request and wait for response
 *
 * Results:
 *      reply code and attributes list or error
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */
static int RadiusCmd(ClientData arg,  Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Server *server = (Server*)arg;
    fd_set rfds;
    Ns_DString ds;
    int retries = 3;
    int timeout = 2;
    struct timeval tm;
    int i, fd, id, len, port, n, vendor;
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    int code = RADIUS_ACCESS_REQUEST;
    unsigned char buffer[RADIUS_BUFFER_LEN];
    RadiusHeader *hdr;
    RadiusVector vector;
    RadiusAttr *attr, *vp = 0;
    RadiusClient *client = 0;
    RadiusUser *user;
    RadiusDict *dict = 0;
    RadiusValue *value;
    RadiusRequest *req;
    enum commands {
        cmdSend, cmdReqGet, cmdReqSet, cmdReqList,
        cmdDictList, cmdDictGet, cmdDictDel, cmdDictAdd, cmdDictValue, cmdDictLabel,
        cmdClientAdd, cmdClientList, cmdClientDel, cmdClientGet,
        cmdUserAdd, cmdUserFind, cmdUserDel, cmdUserList, cmdUserAttrFind,
        cmdReset
    };
    static const char *sCmd[] = {
        "send", "reqget", "reqset", "reqlist",
        "dictlist", "dictget", "dictdel", "dictadd", "dictvalue", "dictlabel",
        "clientadd", "clientlist", "clientdel", "clientget",
        "useradd", "userfind", "userdel", "userlist", "userattrfind",
        "reset",
        0
    };
    int cmd;

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "args");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, &cmd) != TCL_OK) {
        return TCL_ERROR;
    }

    switch (cmd) {
     case cmdSend:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "host port secret ?Code code? ?Retries retries? ?Timeout timeout? ?attr value? ...");
            return TCL_ERROR;
        }
        if (!(port = atoi(Tcl_GetString(objv[3])))) {
            port = RADIUS_AUTH_PORT;
        }
        if (Ns_GetSockAddr((struct sockaddr_in*)&sa, Tcl_GetString(objv[2]), port) != NS_OK) {
            Tcl_AppendResult(interp, "noHost: unknown host: ", Tcl_GetString(objv[2]), 0);
            return TCL_ERROR;
        }
        for (i = 5;i < objc - 1;i += 2) {
            if (!strcasecmp(Tcl_GetString(objv[i]), "Code")) {
                code = atoi(Tcl_GetString(objv[i+1]));
            } else
            if (!strcasecmp(Tcl_GetString(objv[i]), "Retries")) {
                retries = atoi(Tcl_GetString(objv[i+1]));
            } else
            if (!strcasecmp(Tcl_GetString(objv[i]), "Timeout")) {
                timeout = atoi(Tcl_GetString(objv[i+1]));
            } else {
              if ((attr = RadiusAttrCreate(server, Tcl_GetString(objv[i]), -1, 0, Tcl_GetString(objv[i+1]), -1))) {
                RadiusAttrLink(&vp, attr);
              } else {
                Tcl_AppendResult(interp, "unknown attribute ", Tcl_GetString(objv[i]), " ", Tcl_GetString(objv[i+1]), 0);
                return TCL_ERROR;
              }
            }
        }
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            Tcl_AppendResult(interp, "noResponse: ", strerror(errno), 0);
            RadiusAttrFree(&vp);
            return -1;
        }
        // Build an request
        hdr = (RadiusHeader *)buffer;
        RadiusVectorCreate(vector);
        RadiusHeaderPack(hdr, 0, code, vector, vp, (char*)Tcl_GetString(objv[4]));
        RadiusAttrFree(&vp);
        memcpy(vector, hdr->vector, RADIUS_VECTOR_LEN);
        id = hdr->id;
again:
        if (sendto(fd, (char *)hdr, ntohs(hdr->length), 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_in)) <= 0) {
            Tcl_AppendResult(interp, "noResponse: ", strerror(errno), 0);
            close(fd);
            return TCL_ERROR;
        }
        tm.tv_usec = 0L;
        tm.tv_sec = timeout;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        if (select(fd + 1, &rfds, 0, 0, &tm) < 0) {
            if (errno == EINTR) goto again;
            Tcl_AppendResult(interp, "noResponse: ", strerror(errno), 0);
            close(fd);
            return TCL_ERROR;
        }
        if (!FD_ISSET(fd, &rfds)) {
            if (--retries > 0) goto again;
            Tcl_AppendResult(interp, "noResponse: timeout", 0);
            close(fd);
            return TCL_ERROR;
        }
        if ((len = recvfrom(fd, (char *)buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, (socklen_t*)&salen)) <= 0) {
            Tcl_AppendResult(interp, "noResponse: ", strerror(errno), 0);
            close(fd);
            return TCL_ERROR;
        }
        close(fd);
        // Verify that id (seq. number) matches what we sent
        if (hdr->id != (u_char)id || len < ntohs(hdr->length)) {
            Tcl_AppendResult(interp, "noResponse: ID/length does not match", 0);
            return TCL_ERROR;
        }
        // Verify reply md5 digest
        if (RadiusVectorVerify(hdr, vector, Tcl_GetString(objv[4]))) {
            Tcl_AppendResult(interp, "noResponse: invalid reply digest", 0);
            return TCL_ERROR;
        }
        Ns_DStringInit(&ds);
        Ns_DStringPrintf(&ds, "code %d id %d ipaddr %s ", hdr->code, hdr->id, ns_inet_ntoa(sa.sin_addr));
        if ((vp = RadiusAttrParse(server, hdr, len, Tcl_GetString(objv[4])))) {
            RadiusAttrPrintf(vp, &ds, 1, 1);
            RadiusAttrFree(&vp);
        }
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdDictList:
        Ns_DStringInit(&ds);
        RadiusDictPrintf(server, &ds);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdDictAdd:
        if (objc < 6) {
            Tcl_WrongNumArgs(interp, 2, objv, "name attr vendor type valname valnum ...");
            return TCL_ERROR;
        }
        if (!strcmp(Tcl_GetString(objv[5]), "string")) {
            n = RADIUS_TYPE_STRING;
        } else
        if (!strcmp(Tcl_GetString(objv[5]), "filter")) {
            n = RADIUS_TYPE_FILTER_BINARY;
        } else
        if (!strcmp(Tcl_GetString(objv[5]), "integer")) {
            n = RADIUS_TYPE_INTEGER;
        } else
        if (!strcmp(Tcl_GetString(objv[5]), "ipaddr")) {
            n = RADIUS_TYPE_IPADDR;
        } else
        if (!strcmp(Tcl_GetString(objv[5]), "date")) {
            n = RADIUS_TYPE_DATE;
        } else {
            n = atoi(Tcl_GetString(objv[5]));
        }
        dict = RadiusDictFind(server, 0, atoi(Tcl_GetString(objv[3])), atoi(Tcl_GetString(objv[4])), 0);
        if (!dict) {
            dict = RadiusDictAdd(server, Tcl_GetString(objv[2]), atoi(Tcl_GetString(objv[3])), atoi(Tcl_GetString(objv[4])), n);
        }
        if (dict) {
            for (i = 6; i < objc - 1; i+= 2) {
                value = (RadiusValue*)ns_calloc(1, sizeof(RadiusValue));
                strncpy(value->name, Tcl_GetString(objv[i]), RADIUS_STRING_LEN);
                value->value = atoi(Tcl_GetString(objv[i+1]));
                value->next = dict->values;
                dict->values = value;
            }
        }
        break;

     case cmdDictValue:
        if (objc < 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "name vendor label");
            return TCL_ERROR;
        }
        dict = RadiusDictFind(server, Tcl_GetString(objv[2]), -1, atoi(Tcl_GetString(objv[3])), 0);
        if (dict) {
            for (value = dict->values; value; value = value->next) {
                if (!strcasecmp(value->name, Tcl_GetString(objv[4]))) {
                    Tcl_SetObjResult(interp, Tcl_NewIntObj(value->value));
                    return TCL_OK;
                }
            }
        }
        Tcl_AppendResult(interp, Tcl_GetString(objv[4]), 0);
        break;

     case cmdDictLabel:
        if (objc < 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "namr vendor num");
            return TCL_ERROR;
        }
        dict = RadiusDictFind(server, Tcl_GetString(objv[2]), -1, atoi(Tcl_GetString(objv[3])), 0);
        if (dict) {
            n = atoi(Tcl_GetString(objv[4]));
            for (value = dict->values; value; value = value->next) {
                if (value->value == n) {
                    Tcl_AppendResult(interp, value->name, 0);
                    return TCL_OK;
                }
            }
        }
        Tcl_AppendResult(interp, Tcl_GetString(objv[4]), 0);
        break;

     case cmdDictGet:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name|attr ?vendor?");
            return TCL_ERROR;
        }
        dict = RadiusDictFind(server, Tcl_GetString(objv[2]), -1, objc > 3 ? atoi(Tcl_GetString(objv[3])) : -1, 0);
        if (dict) {
            char buffer[256];
            sprintf(buffer, "%s %d %d", dict->name, dict->vendor, dict->type);
            Tcl_AppendResult(interp, buffer, 0);
        }
        break;

     case cmdDictDel:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "del name|attr ?vendor?");
            return TCL_ERROR;
        }
        dict = RadiusDictFind(server, Tcl_GetString(objv[2]), -1, objc > 3 ? atoi(Tcl_GetString(objv[3])) : 0, 1);
        while (dict->values) {
            value = dict->values->next;
            ns_free(dict->values);
            dict->values = value;
        }
        ns_free(dict);
        break;

     case cmdClientGet:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "host");
            return TCL_ERROR;
        }
        if (Ns_GetSockAddr(&sa, (char*)Tcl_GetString(objv[2]), 0) == NS_OK && (client = RadiusClientFind(server, sa.sin_addr, 0))) {
            Tcl_AppendResult(interp, client->secret, 0);
        }
        break;

     case cmdClientAdd:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "host secret");
            return TCL_ERROR;
        }
        RadiusClientAdd(server, (char*)Tcl_GetString(objv[2]), (char*)Tcl_GetString(objv[3]));
        break;

     case cmdClientDel:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "host");
            return TCL_ERROR;
        }
        if (Ns_GetSockAddr(&sa, Tcl_GetString(objv[2]), 0) == NS_OK) {
            client = RadiusClientFind(server, sa.sin_addr, 1);
        }
        ns_free(client);
        break;

     case cmdClientList:
        Ns_DStringInit(&ds);
        RadiusClientPrintf(server, &ds);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdUserList:
        Ns_DStringInit(&ds);
        RadiusUserList(server, objc > 2 ? Tcl_GetString(objv[2]) : 0, &ds);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdUserFind:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        Ns_DStringInit(&ds);
        if (RadiusUserFind(server, Tcl_GetString(objv[2]), &ds)) {
            Tcl_AppendResult(interp, ds.string, 0);
        }
        Ns_DStringFree(&ds);
        break;

     case cmdUserAttrFind:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name attr ?inreply?");
            return TCL_ERROR;
        }
        Ns_DStringInit(&ds);
        if (RadiusUserAttrFind(server, Tcl_GetString(objv[2]), &ds, Tcl_GetString(objv[3]), objc > 4)) {
            Tcl_AppendResult(interp, ds.string, 0);
        }
        Ns_DStringFree(&ds);
        break;

     case cmdUserAdd:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name checkattrs ?replyattrs?");
            return TCL_ERROR;
        }
        if ((user = RadiusUserAdd(server, Tcl_GetString(objv[2])))) {
            RadiusAttr *attr;
            Tcl_Obj *key, *val;
            Tcl_ListObjLength(0, objv[3], &len);
            for (i = 0; i < len; i+= 2) {
                if (Tcl_ListObjIndex(0, objv[3], i, &key) == TCL_OK &&
                    Tcl_ListObjIndex(0, objv[3], i+1, &val) == TCL_OK && key && val) {
                    if ((attr = RadiusAttrCreate(server, Tcl_GetString(key), -1, -1, Tcl_GetString(val), -1))) {
                        RadiusAttrLink(&user->config, attr);
                    }
                }
            }
            if (objc > 4) {
                Tcl_ListObjLength(0, objv[4], &len);
                for (i = 0; i < len; i+= 2) {
                    if (Tcl_ListObjIndex(0, objv[4], i, &key) == TCL_OK &&
                        Tcl_ListObjIndex(0, objv[4], i+1, &val) == TCL_OK && key && val) {
                        if ((attr = RadiusAttrCreate(server, Tcl_GetString(key), -1, -1, Tcl_GetString(val), -1))) {
                            RadiusAttrLink(&user->reply, attr);
                        }
                    }
                }
            }
        }
        break;

     case cmdUserDel:
        RadiusUserDel(server, objc > 2 ? Tcl_GetString(objv[2]) : 0);
        break;

     case cmdReqGet:
        req = (RadiusRequest*)Ns_TlsGet(&radiusTls);
        if (!req) {
            break;
        }
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name ?vendor?");
            return TCL_ERROR;
        }
        vendor = -1;
        if (objc > 3) {
            vendor = atoi(Tcl_GetString(objv[3]));
        }
        Ns_DStringInit(&ds);
        if (!strcmp(Tcl_GetString(objv[2]), "code")) {
            Ns_DStringPrintf(&ds, "%d", req->req_code);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "id")) {
            Ns_DStringPrintf(&ds, "%d", req->req_id);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "ipaddr")) {
            Ns_DStringAppend(&ds, ns_inet_ntoa(req->sa.sin_addr));
        } else
        if ((attr = RadiusAttrFind(req->req, Tcl_GetString(objv[2]), -1, vendor))) {
            RadiusAttrPrintf(attr, &ds, 0, 0);
        }
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdReqSet:
        req = (RadiusRequest*)Ns_TlsGet(&radiusTls);
        if (!req) {
            break;
        }
        for (i = 2; i < objc - 1; i += 2) {
            if (!strcasecmp(Tcl_GetString(objv[i]), "code")) {
                req->reply_code = atoi(Tcl_GetString(objv[i+1]));
            } else
            if ((attr = RadiusAttrCreate(server, Tcl_GetString(objv[i]), -1, -1, Tcl_GetString(objv[i+1]), -1))) {
                RadiusAttrLink(&req->reply, attr);
            }
        }
        break;

     case cmdReqList:
        req = (RadiusRequest*)Ns_TlsGet(&radiusTls);
        if (!req) {
            break;
        }
        Ns_DStringInit(&ds);
        Ns_DStringPrintf(&ds, "code %d id %d ipaddr %s ", req->req_code, req->req_id, ns_inet_ntoa(req->sa.sin_addr));
        RadiusAttrPrintf(req->req, &ds, 1, 1);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdReset:
        server->errors = 0;
        break;
    }
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusRequestProcess --
 *
 *	Tcl handler for a radius requests
 *
 * Results:
 *	None.
 *
 * Side effects:
 *      Sends reply back to the client
 *----------------------------------------------------------------------
 */

static void RadiusRequestProcess(RadiusRequest *req)
{
    Tcl_Interp *interp = Ns_TclAllocateInterp(req->server->name);

    Ns_TlsSet(&radiusTls, req);

    if (Tcl_Eval(interp, req->server->proc) != TCL_OK) {
        Ns_TclLogError(interp);
    }
    Ns_TclDeAllocateInterp(interp);
    Ns_TlsSet(&radiusTls, 0);
    RadiusRequestReply(req);
}

static RadiusRequest *RadiusRequestCreate(Server *server, SOCKET sock, char *buf, int buflen)
{
    int len;
    RadiusAttr *attrs;
    RadiusRequest *req;
    RadiusClient *client;
    struct sockaddr_in sa;
    RadiusHeader *hdr = (RadiusHeader*)buf;
    socklen_t salen = sizeof(struct sockaddr_in);

    if ((len = recvfrom(sock, buf, buflen, 0, (struct sockaddr*)&sa, &salen)) <= 0) {
        if (server->errors >= 0 && server->errors++ < 10) {
            Ns_Log(Error, "RadiusProc: radius: recvfrom error: %s", strerror(errno));
        }
        return NULL;
    }
    if (!(client = RadiusClientFind(server, sa.sin_addr, 0))) {
        if (server->errors >= 0 && server->errors++ < 100) {
            Ns_Log(Error, "RadiusRequestCreate: unknown request from %s", ns_inet_ntoa(sa.sin_addr));
        }
        return NULL;
    }
    if (len < ntohs(hdr->length)) {
        if (server->errors >= 0 && server->errors++ < 100) {
            Ns_Log(Error, "RadiusRequestCreate: bad packet length from %s", ns_inet_ntoa(sa.sin_addr));
        }
        return NULL;
    }
    if (!(attrs = RadiusAttrParse(server, hdr, len, client->secret))) {
        if (server->errors >= 0 && server->errors++ < 100) {
            Ns_Log(Error, "RadiusRequestCreate: invalid request from %s", ns_inet_ntoa(sa.sin_addr));
        }
        return NULL;
    }
    // Allocate request structure
    req = (RadiusRequest*)ns_calloc(1, sizeof(RadiusRequest));
    req->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    // Bind to specified IP address
    if (server->address) {
        bind(req->sock, (struct sockaddr*)&server->sa, sizeof(server->sa));
    }
    req->req = attrs;
    req->client = client;
    req->server = server;
    req->req_id = hdr->id;
    req->req_code = hdr->code;
    req->req_length = len;
    req->reply_code = RADIUS_ACCESS_REJECT;
    req->buffer = buf;
    req->buffer_length = buflen;
    memcpy(&req->sa, &sa, sizeof(sa));
    memcpy(req->vector, hdr->vector, RADIUS_VECTOR_LEN);
    return req;
}

static void RadiusRequestFree(RadiusRequest *req)
{
    if (req) {
        if (req->sock > 0) {
            close(req->sock);
        }
        RadiusAttrFree(&req->req);
        RadiusAttrFree(&req->reply);
        ns_free(req);
    }
}

static int RadiusRequestReply(RadiusRequest *req)
{
    RadiusHeader *hdr = (RadiusHeader*)req->buffer;
    req->reply_length = RadiusHeaderPack(hdr, req->req_id, req->reply_code, req->vector, req->reply, req->client->secret);
    return sendto(req->sock, req->buffer, ntohs(hdr->length), 0, (struct sockaddr*)&req->sa, sizeof(struct sockaddr_in));
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusInit --
 *
 *	Initializes RADIUS subsystem,  default dictionary
 *
 * Results:
 *	None
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */


static void RadiusInit(Server *server)
{
   RadiusDictAdd(server, "User-Name", 1, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "User-Password", 2, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "CHAP-Password", 3, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "NAS-IP-Address", 4, 0, RADIUS_TYPE_IPADDR);
   RadiusDictAdd(server, "NAS-Port", 5, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Service-Type", 6, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-Protocol", 7, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-IP-Address", 8, 0, RADIUS_TYPE_IPADDR);
   RadiusDictAdd(server, "Framed-IP-Netmask", 9, 0, RADIUS_TYPE_IPADDR);
   RadiusDictAdd(server, "Framed-Routing", 10, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Filter-Id", 11, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-MTU", 12, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-Compression", 13, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Login-IP-Host",  14, 0, RADIUS_TYPE_IPADDR);
   RadiusDictAdd(server, "Login-Service",  15, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Login-Port", 16, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Old-Password", 17, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Reply-Message", 18, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Login-Callback-Number", 19, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-Callback-Id", 20, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-Route", 22, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-IPX-Network", 23, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "State", 24, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Class", 25, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Vendor-Specific", 26, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Session-Timeout", 27, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Idle-Timeout", 28, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Termination-Action", 29, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Called-Station-Id", 30, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Calling-Station-Id", 31, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "NAS-Identifier", 32, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Proxy-State", 33, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Login-LAT-Service", 34, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Login-LAT-Node", 35, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Login-LAT-Group", 36, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-AppleTalk-Link", 37, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-AppleTalk-Network", 38, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-AppleTalk-Zone", 39, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "CHAP-Challenge", 60, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "NAS-Port-Type", 61, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Port-Limit", 62, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Status-Type", 40, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Delay-Time", 41, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Input-Octets", 42, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Output-Octets", 43, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Session-Id", 44, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Acct-Authentic", 45, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Session-Time", 46, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Input-Packets", 47, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Output-Packets", 48, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Terminate-Cause", 49, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "User-Id", 99, 0, RADIUS_TYPE_STRING);
}
