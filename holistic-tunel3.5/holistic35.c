/*
** HVTunnel.c: HTTP Tunneling NSAPI SAF
** 
** HolisticView - MetaKnowledge 
** Copyright AGarcia - 2003,2004,2005,2006,2009 
**
** ------------------------------------------------------------
** Version: 1.1  (2003.02.23)
** Version: 1.5  (2006.04.19)
** Version: 2.0  (2007.01.01)
** Version: 3.0  (2009.06.01)
** Version: 3.5  (2009.07.21)
** Version: 4.0  (2009.08.01)
** Release: a
** ------------------------------------------------------------
** !\file holistic35.c
** !\brief NSAPI Reverse Proxy Plugin & Multithreaded Test Client.
** 
** 
*/

/*
** BEGIN MULTIPLATAFORM DEFINES
*/
#ifdef XP_WIN32
#define NSAPI_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define NSAPI_PUBLIC
#endif /* !XP_WIN32 */
/*
** END MULTIPLATAFORM DEFINES
*/

/*
** BEGIN NSAPI SAF INCLUDES
*/
#ifndef _TEST_CASES_
#include "nsapi.h"
#include "base/util.h"       
#include "frame/protocol.h"  
#include "base/file.h"       
#include "base/buffer.h"     
#include "frame/log.h"
#endif
/*
** END NSAPI SAF INCLUDES
*/

#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>



#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

/*
** ------------------------------------------------------------
** BEGIN NSAPI Hacks
** ------------------------------------------------------------
*/
#define NSAPI_GETMETHOD(r)		(r)->method_num
/*
** ------------------------------------------------------------
** END NSAPI Hacks
** ------------------------------------------------------------
*/

/*
// BEGIN Holistic JcdaPlg custom defines and messages
*/
#define HVT_MSG_SIGNATURE			"Holistic JcdaPlg 3.5.0.1.2"
#define HVT_MSG_BOOTSTRAP			"Holistic JcdaPlg::Init"
#define HVT_MSG_STARTEDUP			"Holistic JcdaPlg::started up"
#define HVT_MSG_BOOTERROR			"Holistic JcdaPlg::could not be started"


#define HVT_FNC_HVT_INIT			"JcdaPlg::KamanuBootstrap"
#define HVT_FNC_HVT_SHND			"JcdaPlg::KamanuServiceHandler"
#define HVT_FNC_HVT_PHND			"JcdaPlg::KamanuPathCheckHandler"
#define HVT_FNC_HVT_PERF			"JcdaPlg::PerfLogger"
#define HVT_FNC_HVT_LOGG			"JcdaPlg::LoggerWrapper"



/* BEGIN SECTION PARAMETER NAMES */
#define HVT_PN_INIT_BOOTSTRAP			"bootstrap"


/* END SECTION PARAMETER NAMES */

/* BEGIN SECTION AUX */
#define HTTP_STR_GET	"GET"
#define HTTP_STR_POST	"POST"
#define HTTP_STR_HEAD	"HEAD"
#define HTTP_STR_PUT	"PUT"

#define HTTP_ID_GET		0
#define HTTP_ID_POST	1
#define HTTP_ID_HEAD	2
#define HTTP_ID_PUT		3


#define CODE_LF		0x0A
#define CODE_RT		0x0D
#define CODE_SP		0x20


/*
** ------------------------------------------------------------
** BEGIN HTTP headers defines
** ------------------------------------------------------------
*/
#define HV_HTTP_COOKIE			"cookie"
#define HV_HTTP_QUERY			"query"
#define HV_HTTP_URI			"uri"
#define HV_HTTP_CONTENT_TYPE		"content-type"
#define HV_HTTP_CONTENT_LENGTH		"content-length"
#define HV_HTTP_USER_AGENT		"user-agent"
#define HV_HTTP_METHOD			"method"
#define HV_HTTP_DATA_REMOVED		"data-removed"
#define HV_HTTP_CLF_REQUEST		"clf-request"
#define HV_HTTP_SET_COOKIE		"set-cookie"
#define HV_HTTP_SET_CCOOKIE		"Set-Cookie"
#define HV_HTTP_AUTH_CERT		"auth-cert"
#define HVT_LOGON_APPLID		"logon-applid"
#define HVT_APPLID_ERROR		"error"
#define HVT_COOKIE_ALTEONP		"AlteonP"
#define HVT_COOKIE_PERSISTENCE		"JcdaCookie"            // @CHID(20111005) Added 05/10/2011, Persistence cookie
#define HVT_COOKIE_SMS			"CookieSMS"		// @CHID(20110317) Added 17/03/2011, SMS Auth
#define HVT_TEXT_HTML			"text/html"

/*
** ------------------------------------------------------------
** END HTTP headers defines
** ------------------------------------------------------------
*/

/*
** ------------------------------------------------------------
** BEGIN Entrust http headers definition
** ------------------------------------------------------------
*/

#define	ENTRUST_PREFIX			"entrust"
#define	ENTRUST_PREFIX_LEN		7
	
#define ENTRUST_CLIENT_INFO		"entrust-client-info"
#define ENTRUST_CLIENT_IP		"entrust-client-ip"
#define ENTRUST_CLIENT			"entrust-client"
#define ENTRUST_CLIENT_CERTIFICATE	"entrust-client-certificate"
#define ENTRUST_SERVER			"entrust-server"

/*
** ------------------------------------------------------------
** END Entrust http headers definition
** ------------------------------------------------------------
*/


/*
** ------------------------------------------------------------
** BEGIN Entrust truepass headers definition
** ------------------------------------------------------------
*/

#define TRUEPASS_CLIENT_CERTIFICATE			"TPSignCertificate"

/*
** ------------------------------------------------------------
** END Entrust truepass headers definition
** ------------------------------------------------------------
*/



/*
// END HVTunnel custom defines
*/


/*
** ------------------------------------------------------------
** BEGIN HVTunnel Log masks declaration
** ------------------------------------------------------------
*/

#define HVT_LOGMASK_TIMERS_CONN		"Connect time=%f seconds" 
#define HVT_LOGMASK_TIMERS_TRAN		"Elapsed time=%f seconds" 
#define HVT_LOGMASK_MEMALLOCERR		"Could not allocate %d bytes of memory for variable (%s)" 
#define HVT_LOGMASK_CURLINITERR		"libCURL curl_easy_init has failed" 
#define HVT_LOGMASK_CURLERRORCODE	"libCURL returns error code=%d"
#define HVT_LOGMASK_NOMETHOD		"Could not get HTTP METHOD - aborting" 
#define HVT_LOGMASK_NOAPPLID		"Could not get logon applid - aborting" 
#define HVT_LOGMASK_NOURI		"Could not get URI in request - aborting" 
#define HVT_LOGMASK_NOQUERY		"Could not get QUERY in request - aborting" 
#define HVT_LOGMASK_NOCONTENTLEN	"Could not get CONTENT_LENGHT in request - aborting" 
#define HVT_LOGMASK_NOCLFREQUEST	"Could not get CLF_REQUEST in request - aborting" 
#define HVT_LOGMASK_PATHCHECKSIGN	"Entering PathCheck SAF" 
#define HVT_LOGMASK_SERVICESIGN		"Entering Service SAF" 
#define HVT_LOGMASK_DUMPCONFIG		"Config option NAME (%s) VALUE (%s)"
#define HVT_LOGMASK_QUERYATTACK		"The Query string may be some kind of attack"

/*
** ------------------------------------------------------------
** END HVTunnel Log masks declaration
** ------------------------------------------------------------
*/


/*
** ------------------------------------------------------------
** BEGIN HVTunnel Log level declaration
** ------------------------------------------------------------
*/
#define HVT_LOGGER_NONE				-1
#define HVT_LOGGER_WARN				0
#define HVT_LOGGER_MISCONFIG		1
#define HVT_LOGGER_SECURITY			2
#define HVT_LOGGER_FAILURE			3
#define HVT_LOGGER_CATASTROPHE		4
#define HVT_LOGGER_INFORM			5
#define HVT_LOGGER_VERBOSE			6

/*
** ------------------------------------------------------------
** END HVTunnel Log level declaration
** ------------------------------------------------------------
*/

#define MMRY_INIT_MMRY(MEMSTRUCT)		(MEMSTRUCT.memory= NULL)
#define MMRY_INIT_SIZE(MEMSTRUCT)		(MEMSTRUCT.size= 0)

/*
** ------------------------------------------------------------
** BEGIN HVTunnel Config declarations
** ------------------------------------------------------------
*/
#define HV_HTTP_MAXQUERYLEN		512
#define HV_CFG_MAX_MMALLOC		1024
#define HV_LOG_MAX_MMALLOC		1024
#define HPR_X509_CERT_SIZE		32768

#define HVT_CFG_HTTP_ToURI		"HVTunnel.http.ToURI"
#define HVT_CFG_HTTP_CTOUT		"HVTunnel.http.connect.timeout"
#define HVT_CFG_HTTP_TTOUT		"HVTunnel.http.transfer.timeout"
#define HVT_CFG_HTTP_REDIRECTS		"HVTunnel.http.Redirects"
#define HVT_CFG_HTTP_VERBOSE 		"HVTunnel.http.Verbose"
#define HVT_CFG_HTTP_ENVIRONMENT 	"HVTunnel.http.Environment"
#define HVT_CFG_LOGG_Level		"HVTunnel.Logg.Level"
#define HVT_CFG_LOGG_DmpInit		"HVTunnel.Logg.DumpInit"
#define HVT_CFG_LOGG_PERFORMANCE	"HVTunnel.Logg.Performance"
#define HVT_CFG_BACKEND_URI		"HVTunnel.Backend.URI"
#define HVT_CFG_TEST_FILE		"HVTunnel.Test.Certificate"



/*
** ------------------------------------------------------------
** Type definition - HV Configuration struct
** ------------------------------------------------------------
*/

typedef struct {
	char *m_szName;
	char *m_szValue;
} HV_CONFIG;

#ifndef UINT
typedef unsigned int UINT;
#endif

/*
** ------------------------------------------------------------
** Custon Configuration options 
** ------------------------------------------------------------
*/
HV_CONFIG g_HVConfigArray[] =  {
	{HVT_CFG_HTTP_ToURI,NULL},
	{HVT_CFG_HTTP_CTOUT,NULL},
	{HVT_CFG_HTTP_TTOUT,NULL},
	{HVT_CFG_HTTP_REDIRECTS,NULL},
	{HVT_CFG_HTTP_VERBOSE,NULL},
	{HVT_CFG_HTTP_ENVIRONMENT,NULL},	// @Deprecated
	{HVT_CFG_LOGG_Level,NULL},
	{HVT_CFG_LOGG_DmpInit,NULL},
	{HVT_CFG_LOGG_PERFORMANCE,NULL},
	{HVT_CFG_BACKEND_URI,NULL},
	{HVT_CFG_TEST_FILE, NULL},
	{NULL,NULL}
};

char *g_TestClientCertificate= NULL;

//-------------------------


#define ALLOC_INIT		1
#define ALLOC_BASE		512
#define ALLOC_SANITY	256
#define KMNU_BUFFERSIZE	8192

#define MMRY_INIT_MMRY(MEMSTRUCT)		(MEMSTRUCT.memory= NULL)
#define MMRY_INIT_SIZE(MEMSTRUCT)		(MEMSTRUCT.size= 0)
#define MMRY_INIT_ALL(MEMSTRUCT)		(MEMSTRUCT.memory= NULL, MEMSTRUCT.size= 0)


#ifndef STRDUP
	#define STRDUP strdup
#endif 

#ifndef MALLOC
	#define MALLOC malloc
#endif

#ifndef REALLOC
	#define REALLOC realloc
#endif 

#ifndef FREE
	#define FREE free
#endif


#define HCW_ERROR 	1
#define HCW_OK 		0

/*
** ------------------------------------------------------------
** Http Client Wrapper
** Memory struct for curl callback function
** ------------------------------------------------------------
*/
struct MemoryStruct {
	char *memory;
	size_t size;
};

/*
** ------------------------------------------------------------
** Http Client Wrapper
** A new type to group data needed by Client Wrapper
** ------------------------------------------------------------
*/
typedef struct {
	CURL 					*curl_handle;
	CURLcode				m_curlCode;	
	struct curl_slist 		*m_curlHeaders;
	long 					m_lConnectionTimeout;
	long 					m_lTransferTimeout;
	int 					m_iFollowRedir;
	int 					m_iVerbose;
	struct MemoryStruct 	m_objHeaders;	
	struct MemoryStruct 	m_objContent;
} HttpCWCtx;


/*
** LibCURL Wrapper
**
*/
int hcw_init(HttpCWCtx *CWCtx, long lTransferTimeout, long lConnectionTimeout, int iFollowRedir, int m_iVerbose);
int hcw_cleanup(HttpCWCtx *CWCtx);
int hcw_safety_check(HttpCWCtx *CWCtx);
int hcw_perform(HttpCWCtx *CWCtx, char *pszURI);
long int hcw_getHttpCode(HttpCWCtx *CWCtx);
double hcw_getConnTime(HttpCWCtx *CWCtx);
double hcw_getTotalTime(HttpCWCtx *CWCtx);
size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data);

	
void *newptr_concatenate(int upper_bound, ... );
char *clf2uri(char *pszValue);
char *kmnu_malloc(int iSize) ;
void free_pointer(void *ptr);
char *GetHeaderByName(char *pszHeaderList,char *pszName);

char *hpr_read_cert_b64(char *pszFile);

#ifndef _TEST_CASES_
void (*g_HVLogPtr)(Session *sn, Request *rq, int iLevel, int iCurLevel, char *szModule, char *szFormat, ...);
#endif

/*
** ------------------------------------------------------------
** Standalone test client 
** 
** 
** 
** ------------------------------------------------------------
*/
#ifdef _TEST_CASES_

typedef struct {
	char *URL;
	int clients;
	int requests;
	int think;
} VirtualClient;


void StartVirtualClients(VirtualClient objClient);

/*
** ------------------------------------------------------------
** Program entry point
** ------------------------------------------------------------
*/
int main( int argc, char **argv ) {
	
	VirtualClient m_objMyClient;
	
	m_objMyClient.URL= NULL;
	m_objMyClient.clients= -1;
	m_objMyClient.requests= -1;
	
	while ( argc > 1 ) {
		if( argv[1][0] == '-' ) {
			if( strncasecmp("-url",argv[1],strlen("-url") ) == 0 )
				m_objMyClient.URL= strdup(argv[2]);
				
			if( strncasecmp("-clients",argv[1],strlen("-clients") ) == 0 ) 
				m_objMyClient.clients= atoi(argv[2]);
				
			if( strncasecmp("-requests",argv[1],strlen("-requests") ) == 0 )
				m_objMyClient.requests= atoi(argv[2]);
				
			if( strncasecmp("-think",argv[1],strlen("-think") ) == 0 )
				m_objMyClient.think= atoi(argv[2]);				
		} 
		++argv;
		--argc;
	}

	if( m_objMyClient.URL == NULL || m_objMyClient.clients == -1 || m_objMyClient.requests == -1 ) {
		fprintf(stderr,"Wrong usage!\n");
		exit(8);
	}
	
	
	StartVirtualClients( m_objMyClient );
	getchar();
	
	return(0);
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** hcw_stress
** 
** Thread code
** ------------------------------------------------------------
*/
void *hcw_stress(void *arg) {
	int i= 0;
	char *m_strUserAgent= "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.0; ru; rv:1.8.1.4) Gecko/20070515 Firefox/2.0.0.4";
	HttpCWCtx m_objCWCtx;
	VirtualClient *m_objClient= (VirtualClient *) arg;
	
	
	fprintf(stdout,"starting thread\n");
	for(i= 0; i< m_objClient->requests; i++) {
		
		hcw_init( &m_objCWCtx, 60, 10, 1, 0); 
		
		m_objCWCtx.m_curlHeaders= curl_slist_append(m_objCWCtx.m_curlHeaders, m_strUserAgent);
		hcw_perform(&m_objCWCtx, m_objClient->URL );
		fprintf(stdout,"tid=%d,seq=%d, req= %d, time=%f\n",pthread_self(),i,hcw_getHttpCode(&m_objCWCtx),hcw_getTotalTime(&m_objCWCtx)); 
		hcw_cleanup( &m_objCWCtx ); 
		sleep( m_objClient->think );
		
	}
	fprintf(stdout,"thread=(%d) done!\n",pthread_self());
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** StartVirtualClients
** 
** Stress code 
** ------------------------------------------------------------
*/
void StartVirtualClients(VirtualClient objClient) {
	int i= 0;
	pthread_attr_t attr;
	pthread_t tid;
	void *arg= (void *) &objClient;
	//pthread_attr_init(&attr);
	//pthread_attr_setstacksize(&attr,8192);
	int ret= 0;
	for(i= 0; i< objClient.clients; i++) {
		tid= 0;
		ret= pthread_create(&tid, NULL, hcw_stress, arg);
		fprintf(stdout,"creating thread=(%d) with return code=(%d)\n",tid,ret);
	}
}

#endif

/*
** ------------------------------------------------------------
** Http Client Wrapper
** hcw_init 
** 
** Return: 0 iff succeed, else 1
** ------------------------------------------------------------
*/ 
int hcw_init(HttpCWCtx *CWCtx, long lTransferTimeout, long lConnectionTimeout, int iFollowRedir, int m_iVerbose) {
	CWCtx->curl_handle= NULL;
	CWCtx->m_curlHeaders= NULL;
	CWCtx->m_lConnectionTimeout= lConnectionTimeout; 
	CWCtx->m_lTransferTimeout= lTransferTimeout;
	CWCtx->m_iFollowRedir= iFollowRedir;
	CWCtx->m_iVerbose= m_iVerbose;

	/*
	** ------------------------------------------------------------
	** (a) Both calls init memory structs pointers to NULL 
	** and size to 1. Actually m_objHeaders will hold backend 
	** headers and m_objContent page content.
	** ------------------------------------------------------------
	*/	
	MMRY_INIT_ALL(CWCtx->m_objHeaders);
	MMRY_INIT_ALL(CWCtx->m_objContent);
	
	/*
	** ------------------------------------------------------------
	** (a) Check allocations that could fail. Such construction 
	** is ugly but better than nested ifs. If there are errors 
	** exit leaving program state as before call (ie. reserved
	** memory is freed).
	** ------------------------------------------------------------
	*/	
	//P{CWCtx->m_objHeaders.memory == NULL}
	if( (CWCtx->m_objHeaders.memory= (char *) MALLOC(ALLOC_INIT)) == NULL )
		return(HCW_ERROR);
	//Q{CWCtx->m_objHeaders.memory != NULL}			
	
	//P{CWCtx->m_objHeaders.memory != NULL /\ CWCtx->m_objContent.memory == NULL}
	if( (CWCtx->m_objContent.memory= (char *) MALLOC(ALLOC_INIT)) == NULL ) {
		FREE(CWCtx->m_objHeaders.memory);
		return(HCW_ERROR);
	}
	
	//P{CWCtx->m_objHeaders.memory != NULL /\ CWCtx->m_objContent.memory != NULL /\  CWCtx->curl_handle == NULL }
	if( ( CWCtx->curl_handle= curl_easy_init() ) == NULL ) {
		FREE(CWCtx->m_objHeaders.memory);
		FREE(CWCtx->m_objContent.memory);
		return(HCW_ERROR);
	}
	
	//curl_easy_setopt(CWCtx->curl_handle,CURLOPT_FRESH_CONNECT,1);
	//curl_easy_setopt(CWCtx->curl_handle,CURLOPT_FORBID_REUSE,1); 
	
	//P{CWCtx->m_objHeaders.memory != NULL /\ CWCtx->m_objContent.memory != NULL /\  CWCtx->curl_handle != NULL }	
	
	/*
	** ------------------------------------------------------------
	** Common options setup
	** Since C has short-circuit evaluation its better than
	** nested ifs
	** ------------------------------------------------------------
	*/			
	if( (CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle,CURLOPT_NOSIGNAL,1)) == CURLE_OK &&
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle,CURLOPT_HTTP_VERSION,CURL_HTTP_VERSION_1_0)) == CURLE_OK &&
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle,CURLOPT_CONNECTTIMEOUT, CWCtx->m_lConnectionTimeout)) == CURLE_OK &&
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle,CURLOPT_TIMEOUT, CWCtx->m_lTransferTimeout)) == CURLE_OK && 
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle,CURLOPT_FOLLOWLOCATION, CWCtx->m_iFollowRedir)) == CURLE_OK &&	
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle,CURLOPT_VERBOSE, CWCtx->m_iVerbose)) == CURLE_OK &&	
		/*
		** ------------------------------------------------------------
		** Headers and content memory callback setup
		** ------------------------------------------------------------
		*/			
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle, CURLOPT_HEADERFUNCTION, WriteMemoryCallback)) == CURLE_OK &&	
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle, CURLOPT_WRITEHEADER, (void *) &(CWCtx->m_objHeaders))) == CURLE_OK &&	
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)) == CURLE_OK &&	
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle, CURLOPT_FILE, (void *) &(CWCtx->m_objContent) )) == CURLE_OK )	
			return(HCW_OK);
	else {
		/*
		** ------------------------------------------------------------
		** Ok, we have an error, just leave state as before and drop
		** out.
		** ------------------------------------------------------------
		*/			
		hcw_cleanup(CWCtx);
		return(HCW_ERROR);
	}
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** hcw_cleanup 
** 
** Return: 0 iff succeed, else 1
** ------------------------------------------------------------
*/
int hcw_cleanup(HttpCWCtx *CWCtx) {
	
	if( CWCtx == NULL )
		return(HCW_ERROR);
	
	if( CWCtx->curl_handle != NULL )
		curl_easy_cleanup(CWCtx->curl_handle);

	if(CWCtx->m_objHeaders.memory != NULL)	
		FREE(CWCtx->m_objHeaders.memory);
	if(CWCtx->m_objContent.memory != NULL)	
		FREE(CWCtx->m_objContent.memory);			
	
	if( CWCtx->m_curlHeaders != NULL )
		curl_slist_free_all(CWCtx->m_curlHeaders);
	
	CWCtx->m_curlHeaders= NULL;
	CWCtx->curl_handle= NULL;
	CWCtx->m_objContent.memory= NULL;
	CWCtx->m_objHeaders.memory= NULL;
			
	return(HCW_OK);
}

/*
** ------------------------------------------------------------
** hcw_safety_check
** 
** 
** ------------------------------------------------------------
*/
int hcw_safety_check(HttpCWCtx *CWCtx) {
	
	if( CWCtx == NULL )
		return(HCW_ERROR);

	if(CWCtx->m_objHeaders.memory != NULL)	
		FREE(CWCtx->m_objHeaders.memory);
	if(CWCtx->m_objContent.memory != NULL)	
		FREE(CWCtx->m_objContent.memory);			
	
	if( CWCtx->m_curlHeaders != NULL )
		curl_slist_free_all(CWCtx->m_curlHeaders);
	
	CWCtx->m_curlHeaders= NULL;
	CWCtx->m_objContent.memory= NULL;
	CWCtx->m_objHeaders.memory= NULL;
			
	return(HCW_OK);
}
 
/*
** ------------------------------------------------------------
** Http Client Wrapper
** hcw_addpostdata
** ------------------------------------------------------------
*/
int hcw_addpostdata(HttpCWCtx *CWCtx, char *pszValue, int iSize) {
	char *m_szBuffer= NULL;
	
	
	if( pszValue == NULL )
		return(HCW_OK);
		
	if( (CWCtx->m_curlCode= curl_easy_setopt( CWCtx->curl_handle, CURLOPT_POST, 1L)) == CURLE_OK ) 
		if( (CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle, CURLOPT_POSTFIELDS, pszValue, CURLOPT_POSTFIELDSIZE,iSize)) == CURLE_OK ) 
			return(HCW_OK);
	

	return(HCW_ERROR);			
}
	
/*
** ------------------------------------------------------------
** Http Client Wrapper
** hcw_perform 
** ------------------------------------------------------------
*/
int hcw_perform(HttpCWCtx *CWCtx, char *pszURI) {
			
	if( (CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle, CURLOPT_URL,pszURI)) == CURLE_OK &&
		(CWCtx->m_curlCode= curl_easy_setopt(CWCtx->curl_handle, CURLOPT_HTTPHEADER, CWCtx->m_curlHeaders )) == CURLE_OK &&
		(CWCtx->m_curlCode= curl_easy_perform(CWCtx->curl_handle))  == CURLE_OK ) 
		return(HCW_OK);
	else
		return(HCW_ERROR);			
	
}

/*
** ------------------------------------------------------------
** WriteMemoryCallback
** ------------------------------------------------------------
*/
size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data) {
	register int m_iRealSize= size * nmemb;
	struct MemoryStruct *mem= (struct MemoryStruct *)data;

	mem->memory= (char *)REALLOC(mem->memory, mem->size + m_iRealSize + 1);
	if (mem->memory) {
		memcpy(&(mem->memory[mem->size]), ptr, m_iRealSize);
		mem->size+= m_iRealSize;
		mem->memory[mem->size] = 0;
	} else
		m_iRealSize= -1;
	
	return(m_iRealSize);
}


/*
** ------------------------------------------------------------
** hcw_getHttpCode
** Request http status code
** ------------------------------------------------------------
*/
long int hcw_getHttpCode(HttpCWCtx *CWCtx) {
	long int m_liValue= 0;
	if( CWCtx->curl_handle != NULL )	
		curl_easy_getinfo(CWCtx->curl_handle,CURLINFO_HTTP_CODE,&m_liValue);
	return(m_liValue);
}

/*
** ------------------------------------------------------------
** hcw_getConnTime
** Request connection time
** ------------------------------------------------------------
*/
double hcw_getConnTime(HttpCWCtx *CWCtx) {
	double m_dblConnTime= 0;
	if( CWCtx->curl_handle != NULL )
		curl_easy_getinfo(CWCtx->curl_handle, CURLINFO_CONNECT_TIME, &m_dblConnTime);
		return(m_dblConnTime);
}

/*
** ------------------------------------------------------------
** hcw_getTotalTime
** Request total time
** ------------------------------------------------------------
*/
double hcw_getTotalTime(HttpCWCtx *CWCtx) {
	double m_dblTotalTime= 0;
	if( CWCtx->curl_handle != NULL )
		curl_easy_getinfo(CWCtx->curl_handle, CURLINFO_TOTAL_TIME, &m_dblTotalTime);
	
	return(m_dblTotalTime);	
}

/*
** ------------------------------------------------------------
** hpr_dos2unix
** Removes 0x0d from request header
** ------------------------------------------------------------
*/
void hpr_dos2unix(char *szBuffer) {
	int m_iIndx= 0;
	int m_iCtrl= 0;
	
	for( m_iIndx= 0; m_iIndx< strlen(szBuffer); m_iIndx++ ) {
		if( (m_iCtrl + 1) < strlen(szBuffer) )
			if( szBuffer[ m_iCtrl ] == 0x0d && szBuffer[ m_iCtrl + 1] == 0x0a) m_iCtrl++;
  		szBuffer[ m_iIndx ]= szBuffer[ m_iCtrl ];
  		m_iCtrl++;
  	}
}

/*
** ------------------------------------------------------------
** hpr_remtchars
** Removes line trailing chars
** ------------------------------------------------------------
*/
void hpr_remtchars(char *pszString) {
	int m_iIndx= 0;

	for(m_iIndx= strlen(pszString); iscntrl( pszString[m_iIndx]); m_iIndx--)
		pszString[m_iIndx]= 0;
}

/*
** ------------------------------------------------------------
** hpr_read_cert_b64
** 
** ------------------------------------------------------------
*/
char *hpr_read_cert_b64(char *pszFile)
{
	char m_cCTRL= 0;
	FILE *m_fpFile= NULL;
	char m_szLine[1024];
	char m_szBuffer[HPR_X509_CERT_SIZE];
	int m_iIndx= 0;
	int m_iNLen= 0;

	memset(m_szBuffer,0, HPR_X509_CERT_SIZE);
	memset(m_szLine,0, 1024);
	
	if( (m_fpFile= fopen(pszFile,"r")) != NULL) {
		while( (m_cCTRL= fgetc(m_fpFile)) != EOF) {
			ungetc(m_cCTRL,m_fpFile);
			fgets(m_szLine,HV_CFG_MAX_MMALLOC,m_fpFile);
			strcat(m_szBuffer,m_szLine);
			
		}
		fclose(m_fpFile);	
	}

	return( STRDUP( m_szBuffer ) );
}

/*
** ------------------------------------------------------------
** hpr_loadconfig
** Reads bootstrap configuration file
** ------------------------------------------------------------
*/
void hpr_loadconfig(char *pszBootstrap,HV_CONFIG *m_HVConfig)
{
	char m_cCTRL= 0;
	FILE *m_fpFile= NULL;
	char *m_szBuffer= (char *) MALLOC(HV_CFG_MAX_MMALLOC);
	int m_iIndx= 0;
	int m_iNLen= 0;

	if( (m_fpFile= fopen(pszBootstrap,"r")) != NULL) {
		while( (m_cCTRL= fgetc(m_fpFile)) != EOF) {
			ungetc(m_cCTRL,m_fpFile);
			memset(m_szBuffer,0,HV_CFG_MAX_MMALLOC);
			fgets(m_szBuffer,HV_CFG_MAX_MMALLOC,m_fpFile);
			hpr_remtchars(m_szBuffer);
			for(m_iIndx= 0; m_HVConfig[m_iIndx].m_szName != NULL; m_iIndx++) {	
				m_iNLen= strlen(m_HVConfig[m_iIndx].m_szName);
				if(strncasecmp(m_szBuffer,m_HVConfig[m_iIndx].m_szName,m_iNLen) == 0) {
					m_HVConfig[m_iIndx].m_szValue= STRDUP(m_szBuffer+m_iNLen+1);
					break;
				}
			}
		}
	}

	FREE(m_szBuffer);
	fclose(m_fpFile);
}


/*
** ------------------------------------------------------------
** hpr_GetProperty
** Gets bootstrap porperties value by its name
** ------------------------------------------------------------
*/
char *hpr_GetProperty(char *pszName,HV_CONFIG *m_HVConfig) {	
	int m_iIndx= 0;
	int m_iNLen= 0;
	//
	for(m_iIndx= 0; m_HVConfig[m_iIndx].m_szName != NULL; m_iIndx++) {	
		m_iNLen= strlen(m_HVConfig[m_iIndx].m_szName);
		if(strncasecmp(pszName,m_HVConfig[m_iIndx].m_szName,m_iNLen) == 0) break;
	}
	return(m_HVConfig[m_iIndx].m_szValue);
}

/*
** ------------------------------------------------------------
** Interface between NSAPI and libcurl functions
** ------------------------------------------------------------
*/
#ifndef _TEST_CASES_
/*
** ------------------------------------------------------------
** ForwardHeader2Curl
** ------------------------------------------------------------
*/
int ForwardHeader2Curl(char *szHeaderName, Request *rq, struct curl_slist **curlHeader)
{
	UINT	m_uiSize= 0;
	char	*m_szValue= NULL;
	char	*m_szHeader= NULL;	

	if( ( m_szValue= pblock_findval(szHeaderName , rq->headers)) != NULL ) {
		m_uiSize= strlen(m_szValue) + strlen(szHeaderName) + ALLOC_SANITY;

		if( (m_szHeader= (char *) MALLOC(m_uiSize)) != NULL ) {
			memset(m_szHeader,0,m_uiSize);
			util_sprintf(m_szHeader, "%s: %s", szHeaderName, m_szValue);
			*curlHeader= curl_slist_append(*curlHeader, m_szHeader);
			FREE(m_szHeader);
			return( 1 );
		}
	}
	return( 0 );
}

/*
** ------------------------------------------------------------
** ForwardHeadersToCurl
** ------------------------------------------------------------
*/
void ForwardHeadersToCurl(Request *rq, struct curl_slist **curlHeader) {
	struct pb_entry		*m_PBlockParam;
	int 				m_iIndx= 0;
	UINT				m_uiAllocLen= 0;
	char 				*m_szHeader;

	for (m_iIndx=0; m_iIndx< rq->headers->hsize; m_iIndx++) {
		for (m_PBlockParam= rq->headers->ht[m_iIndx]; m_PBlockParam; m_PBlockParam = m_PBlockParam->next) {
			m_uiAllocLen= strlen(m_PBlockParam->param->name) + strlen(m_PBlockParam->param->value) + ALLOC_SANITY;
			m_szHeader= (char *) MALLOC(m_uiAllocLen);
			memset(m_szHeader,0,m_uiAllocLen);
			util_sprintf(m_szHeader,"%s: %s",m_PBlockParam->param->name,m_PBlockParam->param->value);
			*curlHeader= curl_slist_append(*curlHeader, m_szHeader);
			FREE(m_szHeader);
		}
	}
}


/*
** ------------------------------------------------------------
** kmnu_getExistCookie
** ------------------------------------------------------------
*/
int kmnu_getExistCookie (char * szCookieName, Request *rq, Session *sn) {
	char	*m_szCookie= NULL;
	char	*m_szValue= NULL;
	
	if( ( m_szValue= pblock_findval(HV_HTTP_COOKIE , rq->headers)) != NULL ) { 
		if ( ( m_szCookie= util_cookie_find(m_szValue, szCookieName) ) != NULL ) {
			log_error(LOG_INFORM,"JcdaPlg::kmnu_getExistCookie",sn,rq,"SMS CookieSMS (%s) found!",m_szCookie); 
			return( 1 );
		}
	}
		

	log_error(LOG_FAILURE,"JcdaPlg::kmnu_getExistCookie",sn,rq,"SMS Cookie (CookieSMS) NOT found!"); 	
	return( 0 );					
}

/*
** ------------------------------------------------------------
** ForwardCookie2Curl
** ------------------------------------------------------------
*/
int ForwardCookie2Curl(char * szCookieName, Request *rq, struct curl_slist **curlHeader) {
	UINT	m_uiSize= 0;
	char	*m_szCookie= NULL;
	char	*m_szValue= NULL;
	char 	*m_szHeader= NULL;	

	if( ( m_szValue= pblock_findval(HV_HTTP_COOKIE , rq->headers)) != NULL ) {
		if ( ( m_szCookie= util_cookie_find(m_szValue, szCookieName) ) == NULL )
			return( 0 );

		m_uiSize= strlen(m_szValue) + strlen(szCookieName) + ALLOC_SANITY;

		if( (m_szHeader= (char *) MALLOC(m_uiSize)) != NULL ) {
			memset(m_szHeader,0,m_uiSize);
			util_sprintf(m_szHeader, "%s: %s=%s;", HV_HTTP_COOKIE, szCookieName, m_szCookie);
			*curlHeader= curl_slist_append(*curlHeader, m_szHeader);
			FREE(m_szHeader);
			return( 1 );
		}
	}
	return( 0 );
}


/*
** ------------------------------------------------------------
** ReturnHeader2Client
** ------------------------------------------------------------
*/
int ReturnHeader2Client(Request *rq, char *szName, char *szBuffer, int iSize) {
	char *m_szHeader= NULL;
	
	if( (m_szHeader= GetHeaderByName( szBuffer, szName)) != NULL ) {
		pblock_nvinsert( szName, m_szHeader, rq->srvhdrs);
		free_pointer( (void *) m_szHeader);
		return(1);
	}
	return(0);

}

/*
// getPost
// 
//
//
*/
static int getPost(Session *sn,Request *rq, char *pszBufferX, int iCLen) 
{
	UINT m_uiBytes= 0;
	//
	if(iCLen > 0) {
		m_uiBytes= sn->inbuf->cursize - sn->inbuf->pos;
		if(m_uiBytes == 0) {
			m_uiBytes= netbuf_grab(sn->inbuf, iCLen);
			if(m_uiBytes == IO_ERROR || m_uiBytes == IO_EOF) {
				return(-1);
			}
		} 
		if (m_uiBytes > 0) {
			if (m_uiBytes > iCLen) m_uiBytes= iCLen;
			memcpy(pszBufferX, sn->inbuf->inbuf + sn->inbuf->pos, m_uiBytes);
			sn->inbuf->pos+= m_uiBytes;
			if ( m_uiBytes < iCLen ) {
					iCLen-= m_uiBytes;
					getPost(sn,rq,pszBufferX + sn->inbuf->pos,iCLen);
			}
		}
	}
	return(m_uiBytes);
}




/*
** ------------------------------------------------------------
** HVTunnel NSAPI Plugin Functions
** ------------------------------------------------------------
*/

/*
** ------------------------------------------------------------
** ns_log_stats
** Log performance messages on errors file
** ------------------------------------------------------------
*/
void ns_log_stats(Session *sn, Request *rq, double dblConValue, double dblTotValue) {
	log_error(LOG_INFORM,HVT_FNC_HVT_PERF,sn,rq,HVT_LOGMASK_TIMERS_CONN,dblConValue); 
	log_error(LOG_INFORM,HVT_FNC_HVT_PERF,sn,rq,HVT_LOGMASK_TIMERS_TRAN,dblTotValue); 
}


/*
** ------------------------------------------------------------
** ns_logger_wrapper
** A simple wrapper to netscape log system.
** ------------------------------------------------------------
*/
void ns_logger_wrapper(Session *sn, Request *rq, int iLevel, int iCurLevel, char *szModule, char *szFormat, ...) {
	va_list m_Variadic;
	char 	*m_szBuffer= NULL;
	
	if( iCurLevel >= iLevel ) {
		va_start(m_Variadic, szFormat);

		if( ( m_szBuffer= (char *) MALLOC(HV_LOG_MAX_MMALLOC * sizeof(char)) ) != NULL ) {
			memset(m_szBuffer,0,HV_LOG_MAX_MMALLOC * sizeof(char));
			util_vsprintf(m_szBuffer, szFormat, m_Variadic);
			log_error(iLevel,szModule,sn,rq,m_szBuffer); 
			va_end(m_Variadic);
			FREE(m_szBuffer);
		}
		else 
			log_error(LOG_FAILURE,HVT_FNC_HVT_LOGG,sn,rq,HVT_LOGMASK_MEMALLOCERR,(HV_LOG_MAX_MMALLOC * sizeof(char))); 

	}
}


/*
// ns_logger_none
// Don't log anything - do nothing 
//
//
*/
void ns_logger_none(Session *sn, Request *rq, int iLevel, int iCurLevel, char *szModule, char *szFormat, ...){}

/*
// ns_getclientcertificate
// SSL CERT HANDLE
// 
//
*/
#ifdef __cplusplus
extern "C"
#endif
NSAPI_PUBLIC int ns_getclientcertificate(pblock *pb, Session *sn, Request *rq) {
	int m_iReturnCode= REQ_PROCEED;

	log_error(LOG_VERBOSE,"JcdaPlg::ns_getclientcertificate",sn,rq,"conf_getglobals()->Vsecurity_active=%d", conf_getglobals()->Vsecurity_active ); 
	if( conf_getglobals()->Vsecurity_active ) {
		FuncPtr m_pFunctionPointer= func_find("get-client-cert");
		(*m_pFunctionPointer)(pb,sn,rq);
	}
	else
		m_iReturnCode= REQ_NOACTION;
		
	return(m_iReturnCode);	
}


/*
// HVT_Init
// Initial plugin bootstrap  
// 
//
*/
#ifdef __cplusplus
extern "C"
#endif
NSAPI_PUBLIC int HVT_Init(pblock *pb, Session *sn, Request *rq) {
	
	int m_iReturnCode= REQ_PROCEED;
	
	int m_iIndx= 0;
	char *m_szBootstrap= NULL;
	
	if( curl_global_init(CURL_GLOBAL_ALL) != 0 ) {
		log_error(LOG_INFORM,HVT_FNC_HVT_INIT,sn,rq,HVT_MSG_BOOTERROR);
		m_iReturnCode= REQ_ABORTED;
	}
	
	log_error(LOG_INFORM,HVT_FNC_HVT_INIT,sn,rq,HVT_MSG_SIGNATURE); 
	log_error(LOG_INFORM,HVT_FNC_HVT_INIT,sn,rq, curl_version() ); 
	log_error(LOG_INFORM,HVT_FNC_HVT_INIT,sn,rq,HVT_MSG_BOOTSTRAP); 
	
	if( (m_szBootstrap= pblock_findval(HVT_PN_INIT_BOOTSTRAP, pb)) != NULL ) {
		hpr_loadconfig(m_szBootstrap,(HV_CONFIG *) &g_HVConfigArray);

		/*
		** ------------------------------------------------------------
		** Dump configuration variables.
		** ------------------------------------------------------------
		*/
		if( atoi(hpr_GetProperty(HVT_CFG_LOGG_DmpInit,(HV_CONFIG *) &g_HVConfigArray)) != HVT_LOGGER_NONE)
			for(m_iIndx= 0; g_HVConfigArray[m_iIndx].m_szName != NULL; m_iIndx++)
				log_error(LOG_INFORM,HVT_FNC_HVT_INIT,sn,rq,HVT_LOGMASK_DUMPCONFIG,g_HVConfigArray[m_iIndx].m_szName, hpr_GetProperty(g_HVConfigArray[m_iIndx].m_szName,(HV_CONFIG *) &g_HVConfigArray));
	

		if( hpr_GetProperty(HVT_CFG_TEST_FILE,(HV_CONFIG *) &g_HVConfigArray) != NULL )
			g_TestClientCertificate= hpr_read_cert_b64( hpr_GetProperty(HVT_CFG_TEST_FILE,(HV_CONFIG *) &g_HVConfigArray));
			
				
		/*
		**------------------------------------------------------------
		** If log level is none point to a dummy do nothing function
		** ------------------------------------------------------------
		*/
		if( atoi(hpr_GetProperty(HVT_CFG_LOGG_Level,(HV_CONFIG *) &g_HVConfigArray)) == HVT_LOGGER_NONE )
			g_HVLogPtr= ns_logger_none;
		else
			g_HVLogPtr= ns_logger_wrapper;

		/*
		**------------------------------------------------------------
		** The line below logs system correct bootstrap
		** ------------------------------------------------------------
		*/
		log_error(LOG_INFORM,HVT_FNC_HVT_INIT,sn,rq,HVT_MSG_STARTEDUP);
	}
	else {
		log_error(LOG_FAILURE,HVT_FNC_HVT_INIT,sn,rq,HVT_MSG_BOOTERROR);
		m_iReturnCode= REQ_ABORTED;
	}
	return(m_iReturnCode);
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** 
** 
** 
** ------------------------------------------------------------
*/
char *kmnu_getClientCert(pblock *pb, Session *sn, Request *rq) {
	char *m_pblock_certificate= NULL;
	char *m_strdup_certificate= NULL;
	char *m_pblock_cookies= NULL;
	char *m_strdup_cookies= NULL;
	
	
	ns_getclientcertificate(pb,sn,rq);
	
	if( (m_pblock_certificate= pblock_findval(HV_HTTP_AUTH_CERT, rq->vars)) == NULL ) {
		
		log_error(LOG_VERBOSE,"JcdaPlg::kmnu_getClientCert",sn,rq,"Header SSL(auth-cert) is NULL, Trying TPSignCertificate");
		
		if( (m_pblock_cookies= pblock_findval(HV_HTTP_COOKIE, rq->headers)) != NULL ) {
			
			if( (m_strdup_cookies= STRDUP(m_pblock_cookies)) != NULL ) {
				m_pblock_certificate= util_cookie_find(m_strdup_cookies, TRUEPASS_CLIENT_CERTIFICATE);
				FREE(m_strdup_cookies);
			} 			
			
			if(m_pblock_certificate == NULL) {
				log_error(LOG_VERBOSE,"JcdaPlg::kmnu_getClientCert",sn,rq,"SSL(auth-cert) is NULL, Trying Header(entrust-client-certificate)"); 
				m_pblock_certificate= pblock_findval(ENTRUST_CLIENT_CERTIFICATE, rq->headers);
				if( m_pblock_certificate == NULL ) 
					log_error(LOG_VERBOSE,"JcdaPlg::kmnu_getClientCert",sn,rq,"TPSignCertificate is NULL, no more options to try!");
			}
		}
	}

	if( m_pblock_certificate != NULL ) {
		m_strdup_certificate= STRDUP(m_pblock_certificate);
		hpr_dos2unix(m_strdup_certificate);	
	}	
	else
		log_error(LOG_FAILURE,"JcdaPlg::kmnu_getClientCert",sn,rq,"X509 client certificate not found!"); 
		
	return(m_strdup_certificate);				
}	

/*
** ------------------------------------------------------------
** Http Client Wrapper
** kmnu_getClientCertHeader
** 
** 
** ------------------------------------------------------------
*/
char *kmnu_getClientCertHeader(pblock *pb, Session *sn, Request *rq) {
	char *m_strdup_certificate= NULL;
	char *m_pszValue= NULL;

	if( (m_strdup_certificate= kmnu_getClientCert(pb, sn, rq)) != NULL) {
		m_pszValue= (char *) newptr_concatenate(KMNU_BUFFERSIZE,ENTRUST_CLIENT_CERTIFICATE,": ",m_strdup_certificate, (char*) NULL ); 
		FREE(m_strdup_certificate);
	}
	return(m_pszValue);				
}	

/*
** ------------------------------------------------------------
** Http Client Wrapper
** kmnu_isApplidOK
** 
** 
** ------------------------------------------------------------
*/
int kmnu_isApplidOK(char *pszValue) {
	if( pszValue != NULL )
		if ( strcmp( pszValue, HVT_APPLID_ERROR ) == 0 ) 
			return(0);
	
	return(1);	
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** ns_forward_ip
** 
** 
** ------------------------------------------------------------
*/
int ns_forward_ip(pblock *pb, Session *sn, Request *rq) {
	char* remote_ip= NULL;
	if( ( remote_ip= pblock_findval( "ip", sn->client ) ) != NULL ) {
		pblock_nvinsert("Client-ip", remote_ip, rq->headers);
		return(1);
	}
	return(0);
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** ns_forward_sslid
** 
** 
** ------------------------------------------------------------
*/
int ns_forward_sslid(pblock *pb, Session *sn, Request *rq) {
	char* remote_sslid= NULL;
	if( ( remote_sslid= pblock_findval( "ssl-id", sn->client ) ) != NULL ) {
		pblock_nvinsert("$WSSI", remote_sslid, rq->headers);
		return(1);
	}
	return(0);
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** ns_forward_sms
** 
** 
** ------------------------------------------------------------
*/
int ns_forward_sms(pblock *pb, Session *sn, Request *rq) {
	char* remote_cookies= NULL;
	char* remote_sms= NULL;
	if( ( remote_cookies= pblock_findval(HV_HTTP_COOKIE , rq->headers)) != NULL ) { 
		if ( ( remote_sms= util_cookie_find(remote_cookies, "CookieSMS") ) != NULL ) {
			pblock_nvinsert("$SMSID", remote_sms, rq->headers);
			return(1);
		}
	}
	return(0);
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** ns_forward_certificate
** 
** 
** ------------------------------------------------------------
*/
int ns_forward_certificate(pblock *pb, Session *sn, Request *rq) {
	char *m_pszClientCert;
	
	if( ( m_pszClientCert= kmnu_getClientCert(pb, sn, rq)) != NULL ) {
		pblock_nvinsert(ENTRUST_CLIENT_CERTIFICATE, m_pszClientCert, rq->headers);
		free_pointer(m_pszClientCert);
		return(1);
		
	}
	return(0);
	
}

/*
** ------------------------------------------------------------
** free_pointer
** 
** 
** 
** ------------------------------------------------------------
*/
void free_pointer(void *ptr){
	if(ptr != NULL) FREE(ptr);
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** newptr_concatenate
** 
** 
** ------------------------------------------------------------
*/
void *newptr_concatenate(int upper_bound, ... ) {
	va_list arguments= NULL;
    char *m_ptrValue;
    char *m_ptrNewValue= NULL;
    int m_iSize= 0;

	va_start(arguments, upper_bound);

	while((m_ptrValue= va_arg(arguments, char *)) != NULL) {
			m_iSize+= strlen(m_ptrValue);
	}
	va_end(arguments);
	
	arguments= NULL;
	va_start(arguments, upper_bound);
	if( m_iSize < upper_bound ) { 
		m_iSize++;
		if( (m_ptrNewValue= (char *) MALLOC( m_iSize )) != NULL ) {
			memset(m_ptrNewValue,0,m_iSize);
			while((m_ptrValue= va_arg(arguments, char *)) != NULL)
				strcat(m_ptrNewValue,m_ptrValue);
		}
	}
	
	va_end(arguments);
	return(m_ptrNewValue);
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** clf2uri
** 
** 
** ------------------------------------------------------------
*/
char *clf2uri(char *pszValue) {
	char m_pszBuffer[KMNU_BUFFERSIZE];
	char *m_pszPattern= NULL;
	
	memset(m_pszBuffer,0,KMNU_BUFFERSIZE);
	if( pszValue != NULL ) {
		
		m_pszPattern= (char*) regcmp("([(^GET){0,1}|(^POST){0,1}]+)","( +)","(.*)$0","( +)","(HTTP/1\\.[0-9])", (char *) 0 );
		regex(m_pszPattern, pszValue, m_pszBuffer);
		FREE(m_pszPattern);
	}
	
	if(m_pszBuffer[0] != 0) 
		return(STRDUP(m_pszBuffer));
	else
		return(NULL);
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** kmnu_malloc
** 
** 
** ------------------------------------------------------------
*/
char *kmnu_malloc(int iSize) {
	char *m_pszTemp= NULL;
	iSize+= 256;
	if( (m_pszTemp= MALLOC(iSize)) != NULL ) 
		memset(m_pszTemp,0,iSize);
	
	return(m_pszTemp);	
}

/*
** ------------------------------------------------------------
** Http Client Wrapper
** CheckQueryString
** 
** 
** ------------------------------------------------------------
*/
int CheckQueryString(char *pszQuery) {
	return( ( (strlen(pszQuery) <= HV_HTTP_MAXQUERYLEN) ? 1 : 0 ));
}


/*
** ------------------------------------------------------------
** Http Client Wrapper
** indexOf
** 
** 
** ------------------------------------------------------------
*/
UINT indexOf(char *szBuffer, char cChr) {
	UINT m_iIndx= 0;
	//	
	for(m_iIndx= 0; m_iIndx< strlen(szBuffer); m_iIndx++)
		if(szBuffer[m_iIndx] == cChr) break;
	return(m_iIndx);
}


/*
** ------------------------------------------------------------
** Http Client Wrapper
** GetHeaderByName
** 
** 
** ------------------------------------------------------------
*/
char *GetHeaderByName(char *pszHeaderList,char *pszName) {
	UINT i= 0;
	char m_pszBuffer[KMNU_BUFFERSIZE];
	
	i= 0;
	memset(m_pszBuffer,0,KMNU_BUFFERSIZE);
	for(;*pszHeaderList != NULL; pszHeaderList++) {
		if( *pszHeaderList != 0x0d && *pszHeaderList != 0x0a ) { 	
			m_pszBuffer[i++]= *pszHeaderList;
		}
		else if(strlen(m_pszBuffer) > 0 ) {
				if( strncasecmp(pszName, m_pszBuffer, strlen(pszName) ) == 0 	) 
					return(STRDUP(m_pszBuffer+strlen(pszName)+2));
				i= 0;
				memset(m_pszBuffer,0,KMNU_BUFFERSIZE);
			}
	}
	return(NULL);

}


/*
** ------------------------------------------------------------
** KamanuPathCheckHandler
** 
** 
** 
** ------------------------------------------------------------
*/
#ifdef __cplusplus
extern "C"
#endif
NSAPI_PUBLIC int KamanuServiceHandler(pblock *pb, Session *sn, Request *rq) {
	int			m_iReturnCode= REQ_PROCEED;			/* By default allways proceed */

	UINT		m_iContentLen= 0;
	UINT		m_iBytesRead= 0;
	
	HttpCWCtx 	m_objCWCtx;


	/*
	**-------------------------------------------------------------
	** Memory managed by sun one, should not be freed.
	** ------------------------------------------------------------
	*/
	char 			*m_pblock_uri= NULL;					/* Used by pblock_findval 	*/
	char 			*m_pblock_query= NULL;					/* Used by pblock_findval 	*/
	char 			*m_pblock_content_length= NULL;			/* Used by pblock_findval 	*/
	char 			*m_pblock_clf_request= NULL; 			/* Used by pblock_findval 	*/
	char 			*m_pblock_logon_applid;					/* Used by pblock_findval 	*/
	
	/*
	**-------------------------------------------------------------
	** Should be freed
	** ------------------------------------------------------------
	*/
	char 			*m_szRequest= NULL;						/* Used to submit request 	*/	
	char 			*m_szCURL_URI= NULL;					/* Used to submit request 	*/	
	char 			*m_szContentData= NULL;					/* Used to submit request 	*/		


	/*
	** ------------------------------------------------------------
	** HTTP METHOD HANDLE
	** ------------------------------------------------------------
	*/
	switch( NSAPI_GETMETHOD(rq) ) {
		/*
		** ------------------------------------------------------------
		** Handle GET request
		** ------------------------------------------------------------
		*/
		case METHOD_GET: {
			
			if( (m_pblock_uri= pblock_findval(HV_HTTP_URI, rq->reqpb)) != NULL &&
				(m_pblock_query= pblock_findval(HV_HTTP_QUERY, rq->reqpb)) != NULL &&
				(m_pblock_logon_applid= pblock_findval(HVT_LOGON_APPLID, rq->vars)) != NULL &&
				strcmp( m_pblock_logon_applid, HVT_APPLID_ERROR ) != 0 && 
				CheckQueryString(m_pblock_query) &&
				(m_szCURL_URI= (char *) newptr_concatenate(KMNU_BUFFERSIZE,hpr_GetProperty(HVT_CFG_HTTP_ToURI,(HV_CONFIG *) &g_HVConfigArray),m_pblock_uri,"?",m_pblock_query,"&",m_pblock_logon_applid,(char*) NULL )) != NULL ) 
				m_iReturnCode= REQ_PROCEED;
			else
				m_iReturnCode= REQ_ABORTED;
			break;
		}

		/*
		** ------------------------------------------------------------
		** Handle POST request
		** ------------------------------------------------------------
		*/
		case METHOD_POST: {
			if( (m_pblock_content_length= pblock_findval(HV_HTTP_CONTENT_LENGTH, rq->headers)) != NULL &&
				(m_pblock_clf_request= pblock_findval(HV_HTTP_CLF_REQUEST, rq->reqpb)) != NULL &&
				(m_szContentData= kmnu_malloc( (m_iContentLen= atoi(m_pblock_content_length)) )) != NULL &&
				(m_szRequest= clf2uri(m_pblock_clf_request)) != NULL ) {
					pblock_nvinsert(HV_HTTP_DATA_REMOVED, "nothing", rq->vars); 
					m_szCURL_URI= (char *) newptr_concatenate(KMNU_BUFFERSIZE,hpr_GetProperty(HVT_CFG_HTTP_ToURI,(HV_CONFIG *) &g_HVConfigArray),m_szRequest,(char*) NULL );
					FREE(m_szRequest); 
					m_iBytesRead= getPost(sn,rq,m_szContentData,m_iContentLen);
			} else
				m_iReturnCode= REQ_ABORTED;

			break;

		}

	}

	if( m_iReturnCode != REQ_ABORTED && 
		hcw_init( &m_objCWCtx, 
					atol(hpr_GetProperty(HVT_CFG_HTTP_TTOUT,(HV_CONFIG *) &g_HVConfigArray)), 
					atol(hpr_GetProperty(HVT_CFG_HTTP_CTOUT,(HV_CONFIG *) &g_HVConfigArray)), 
					atoi(hpr_GetProperty(HVT_CFG_HTTP_REDIRECTS,(HV_CONFIG *) &g_HVConfigArray)), 
					atoi(hpr_GetProperty(HVT_CFG_HTTP_VERBOSE,(HV_CONFIG *) &g_HVConfigArray))) != HCW_ERROR && 
					hcw_addpostdata( &m_objCWCtx, m_szContentData,m_iBytesRead) != HCW_ERROR ) {
		
			
		ForwardHeader2Curl(HV_HTTP_USER_AGENT, rq, &m_objCWCtx.m_curlHeaders);
		//ForwardCookie2Curl(HVT_COOKIE_ALTEONP, rq, &m_objCWCtx.m_curlHeaders);
		ForwardCookie2Curl(HVT_COOKIE_PERSISTENCE, rq, &m_objCWCtx.m_curlHeaders);
		
		if( hcw_perform(&m_objCWCtx, m_szCURL_URI) != HCW_ERROR &&
			m_objCWCtx.m_curlCode == CURLE_OK &&
			hcw_getHttpCode(&m_objCWCtx) == PROTOCOL_OK &&
			m_objCWCtx.m_objContent.size > 0 ) {

			ns_log_stats(sn, rq, hcw_getConnTime(&m_objCWCtx), hcw_getTotalTime(&m_objCWCtx));
									
			param_free(pblock_remove(HV_HTTP_CONTENT_TYPE, rq->srvhdrs));
			protocol_status(sn, rq, PROTOCOL_OK, NULL);
			
			ReturnHeader2Client(rq, HV_HTTP_CONTENT_TYPE, m_objCWCtx.m_objHeaders.memory, m_objCWCtx.m_objHeaders.size );
			//ReturnHeader2Client(rq, HV_HTTP_CONTENT_LENGTH, m_objCWCtx.m_objHeaders.memory, m_objCWCtx.m_objHeaders.size );
			ReturnHeader2Client(rq, HV_HTTP_SET_CCOOKIE, m_objCWCtx.m_objHeaders.memory, m_objCWCtx.m_objHeaders.size );

			if(protocol_start_response(sn, rq) != REQ_NOACTION)
				(void) net_write(sn->csd, m_objCWCtx.m_objContent.memory, m_objCWCtx.m_objContent.size);
		} else {
			m_iReturnCode= REQ_ABORTED;
			protocol_status(sn, rq, PROTOCOL_SERVER_ERROR, NULL);
			log_error(LOG_FAILURE,"JcdaPlg::KamanuServiceHandler",sn,rq,"Invalid Backend response"); 
		}
		
		hcw_cleanup( &m_objCWCtx ); 
			
	}
	
	free_pointer(m_szContentData);
	free_pointer(m_szCURL_URI);

	return(m_iReturnCode);
}

/*
** ------------------------------------------------------------
** KamanuPathCheckHandler
** 
** 
** 
** ------------------------------------------------------------
*/
#ifdef __cplusplus
extern "C"
#endif
NSAPI_PUBLIC int KamanuPathCheckHandler(pblock *pb, Session *sn, Request *rq) {

	int	m_iReturnCode= 		REQ_NOACTION;	/* By default allways no action to follow plugin chain */

	HttpCWCtx 	m_objCWCtx;
	
	char 		*m_szCURL_URI= NULL;					
	char		*m_szHeader= NULL;
	
	/*
	**-------------------------------------------------------------
	** Memory managed by sun one, should not be freed.
	** ------------------------------------------------------------
	*/
	char 			*m_pblock_query= NULL;					/* Used by pblock_findval 	*/

	/*
	**-------------------------------------------------------------
	** Only must be called at first get method
	** ------------------------------------------------------------
	*/
	if( ISMPOST(rq) )
		return(REQ_NOACTION);


	
	if( (m_pblock_query= pblock_findval(HV_HTTP_QUERY, rq->reqpb)) != NULL &&
		CheckQueryString(m_pblock_query) &&
		(m_szCURL_URI= (char *) newptr_concatenate(KMNU_BUFFERSIZE,hpr_GetProperty(HVT_CFG_BACKEND_URI,(HV_CONFIG *) &g_HVConfigArray),"?",m_pblock_query,(char*) NULL )) != NULL  && 
		ns_forward_certificate(pb,sn,rq)  ) { 
		
		ns_forward_ip(pb,sn,rq);
		
		if( hcw_init( &m_objCWCtx, 
				atol(hpr_GetProperty(HVT_CFG_HTTP_TTOUT,(HV_CONFIG *) &g_HVConfigArray)), 
				atol(hpr_GetProperty(HVT_CFG_HTTP_CTOUT,(HV_CONFIG *) &g_HVConfigArray)), 
				atoi(hpr_GetProperty(HVT_CFG_HTTP_REDIRECTS,(HV_CONFIG *) &g_HVConfigArray)), 
				atoi(hpr_GetProperty(HVT_CFG_HTTP_VERBOSE,(HV_CONFIG *) &g_HVConfigArray))) != HCW_ERROR ) {
					
			ForwardHeadersToCurl(rq, &m_objCWCtx.m_curlHeaders);	
			
			
			if( hcw_perform(&m_objCWCtx, m_szCURL_URI) != HCW_ERROR &&
				m_objCWCtx.m_curlCode == CURLE_OK &&
				hcw_getHttpCode(&m_objCWCtx) == PROTOCOL_OK &&
				m_objCWCtx.m_objContent.size > 0 ) {
					
					ns_log_stats(sn, rq, hcw_getConnTime(&m_objCWCtx), hcw_getTotalTime(&m_objCWCtx));
					
					if( (m_szHeader= GetHeaderByName(m_objCWCtx.m_objHeaders.memory,HVT_LOGON_APPLID)) != NULL ) 
						pblock_nvinsert(HVT_LOGON_APPLID,m_szHeader, rq->vars);
						
					if( !kmnu_isApplidOK(m_szHeader) ) {
						log_error(LOG_FAILURE,"JcdaPlg::KamanuPathCheckHandler",sn,rq,"Auth failure. No valid APPLID"); 
						param_free(pblock_remove(HV_HTTP_CONTENT_TYPE, rq->srvhdrs));
						protocol_status(sn, rq, PROTOCOL_OK, NULL);
						pblock_nvinsert(HV_HTTP_CONTENT_TYPE, HVT_TEXT_HTML, rq->srvhdrs);
						if(protocol_start_response(sn, rq) != REQ_NOACTION) 
							(void) net_write(sn->csd, m_objCWCtx.m_objContent.memory, m_objCWCtx.m_objContent.size);
 						m_iReturnCode= REQ_PROCEED;
					}
			} else {
				m_iReturnCode= REQ_ABORTED;
				protocol_status(sn, rq, PROTOCOL_SERVER_ERROR, NULL);
				log_error(LOG_FAILURE,"JcdaPlg::KamanuPathCheckHandler",sn,rq,"Invalid Backend response"); 
			}
		
			
			hcw_cleanup( &m_objCWCtx ); 	
		}
	}
	
	
	
	free_pointer(m_szCURL_URI);
	free_pointer(m_szHeader);
	
	return(m_iReturnCode);
}

/*
** ------------------------------------------------------------
** KamanuSMSPathCheckHandler
** 
** 
** 
** ------------------------------------------------------------
*/
#ifdef __cplusplus
extern "C"
#endif
NSAPI_PUBLIC int KamanuSMSPathCheckHandler(pblock *pb, Session *sn, Request *rq) {

	int	m_iReturnCode= 		REQ_NOACTION;	/* By default allways no action to follow plugin chain */

	HttpCWCtx 	m_objCWCtx;
	
	char 		*m_szCURL_URI= NULL;					
	char		*m_szHeader= NULL;
	
	/*
	**-------------------------------------------------------------
	** Memory managed by sun one, should not be freed.
	** ------------------------------------------------------------
	*/
	char 			*m_pblock_query= NULL;					/* Used by pblock_findval 	*/

	/*
	**-------------------------------------------------------------
	** Only must be called at first get method
	** ------------------------------------------------------------
	*/
	if( ISMPOST(rq) )
		return(REQ_NOACTION);


	
	if( (m_pblock_query= pblock_findval(HV_HTTP_QUERY, rq->reqpb)) != NULL &&
		CheckQueryString(m_pblock_query) &&
		(m_szCURL_URI= (char *) newptr_concatenate(KMNU_BUFFERSIZE,hpr_GetProperty(HVT_CFG_BACKEND_URI,(HV_CONFIG *) &g_HVConfigArray),"?",m_pblock_query,(char*) NULL )) != NULL && 
			ns_forward_sms(pb,sn,rq) ) { 
				
		log_error(LOG_INFORM,"JcdaPlg::KamanuPathCheckHandler",sn,rq,"About to call BE server!");			
			
		ns_forward_ip(pb,sn,rq);
		ns_forward_sslid(pb,sn,rq);
		
			
		
		if( hcw_init( &m_objCWCtx, 
				atol(hpr_GetProperty(HVT_CFG_HTTP_TTOUT,(HV_CONFIG *) &g_HVConfigArray)), 
				atol(hpr_GetProperty(HVT_CFG_HTTP_CTOUT,(HV_CONFIG *) &g_HVConfigArray)), 
				atoi(hpr_GetProperty(HVT_CFG_HTTP_REDIRECTS,(HV_CONFIG *) &g_HVConfigArray)), 
				atoi(hpr_GetProperty(HVT_CFG_HTTP_VERBOSE,(HV_CONFIG *) &g_HVConfigArray))) != HCW_ERROR ) {
					
			ForwardHeadersToCurl(rq, &m_objCWCtx.m_curlHeaders);	
			
			
			if( hcw_perform(&m_objCWCtx, m_szCURL_URI) != HCW_ERROR &&
				m_objCWCtx.m_curlCode == CURLE_OK &&
				hcw_getHttpCode(&m_objCWCtx) == PROTOCOL_OK &&
				m_objCWCtx.m_objContent.size > 0 ) {
					
					ns_log_stats(sn, rq, hcw_getConnTime(&m_objCWCtx), hcw_getTotalTime(&m_objCWCtx));
					
					if( (m_szHeader= GetHeaderByName(m_objCWCtx.m_objHeaders.memory,HVT_LOGON_APPLID)) != NULL ) 
						pblock_nvinsert(HVT_LOGON_APPLID,m_szHeader, rq->vars);
						
					if( !kmnu_isApplidOK(m_szHeader) ) {
						log_error(LOG_FAILURE,"JcdaPlg::KamanuPathCheckHandler",sn,rq,"Auth failure. No valid APPLID"); 
						param_free(pblock_remove(HV_HTTP_CONTENT_TYPE, rq->srvhdrs));
						protocol_status(sn, rq, PROTOCOL_OK, NULL);
						pblock_nvinsert(HV_HTTP_CONTENT_TYPE, HVT_TEXT_HTML, rq->srvhdrs);
						if(protocol_start_response(sn, rq) != REQ_NOACTION) 
							(void) net_write(sn->csd, m_objCWCtx.m_objContent.memory, m_objCWCtx.m_objContent.size);
 						m_iReturnCode= REQ_PROCEED;
					}
			} else {
				m_iReturnCode= REQ_ABORTED;
				protocol_status(sn, rq, PROTOCOL_SERVER_ERROR, NULL);
				log_error(LOG_FAILURE,"JcdaPlg::KamanuPathCheckHandler",sn,rq,"Invalid Backend response"); 
			}
		
			
			hcw_cleanup( &m_objCWCtx ); 	
		}
	}
	
	
	
	free_pointer(m_szCURL_URI);
	free_pointer(m_szHeader);
	
	return(m_iReturnCode);
}


/*
** ------------------------------------------------------------
** KamanuTestEnvironment
** 
** 
** 
** ------------------------------------------------------------
*/
NSAPI_PUBLIC int KamanuTestEnvironment(pblock *pb, Session *sn, Request *rq) {
	if( g_TestClientCertificate != NULL )
		pblock_nvinsert(ENTRUST_CLIENT_CERTIFICATE, g_TestClientCertificate , rq->headers);

	return(REQ_NOACTION);
}


/*
** ------------------------------------------------------------
** Old NSAPI Path Check Names
** HVT_PathCheckHandler
** 
** 
** ------------------------------------------------------------
*/
NSAPI_PUBLIC int HVT_PathCheckHandler(pblock *pb, Session *sn, Request *rq) {
	return(KamanuPathCheckHandler(pb, sn, rq));
}

/*
** ------------------------------------------------------------
** Old NSAPI Service Check Names
** HVT_ServiceHandler
** 
** 
** ------------------------------------------------------------
*/	
NSAPI_PUBLIC int HVT_ServiceHandler(pblock *pb, Session *sn, Request *rq) {
	return(KamanuServiceHandler(pb, sn, rq));
}	

#endif 

