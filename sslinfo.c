/* sslinfo - SSL information tool
 * Copyright(c) 2018-2023, Daniel Austin MBCS
 *
 * $Id: sslinfo.c 1061 2023-11-27 16:04:19Z dan $
 */

#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/utsname.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#include <openssl/ct.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "ocsp_lcl.h"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { fprintf(stderr, "ERROR: "); ERR_print_errors_fp(stderr); exit(2); }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define	TLS_client_method	SSLv23_client_method
#else
#define HAVE_X509_GET0_EXTENSIONS 1
#endif

/* global variables */
int	ocsp_status	= -1;

static int ocsp_resp_cb(SSL *s, void *arg)
{
	const unsigned char	*p;
	int			len, i;
	long			l;
	OCSP_RESPONSE		*rsp;
	OCSP_BASICRESP		*br = NULL;
	OCSP_RESPDATA		*rd = NULL;
	OCSP_SINGLERESP		*single = NULL;
	OCSP_CERTSTATUS		*cst = NULL;

	len = SSL_get_tlsext_status_ocsp_resp(s, &p);
	if (p == NULL)
	{
		/* no OSCP response */
		ocsp_status = -1;
		return 1;
	}
	rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
	if (rsp == NULL)
	{
		/* unable to parse response */
		ocsp_status = -1;
		return 0;
	}
	l = ASN1_ENUMERATED_get(rsp->responseStatus);
	if (l != 0)
	{
		/* not successful */
		ocsp_status = -1;
		return 0;
	}
	br = OCSP_response_get1_basic(rsp);
	if (!br)
	{
		/* not successful */
		ocsp_status = -1;
		return 0;
	}
	rd = &br->tbsResponseData;
	for (i=0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++)
	{
		if (!sk_OCSP_SINGLERESP_value(rd->responses, i))
			continue;
		single = sk_OCSP_SINGLERESP_value(rd->responses, i);
		cst = single->certStatus;
		if (cst->type == V_OCSP_CERTSTATUS_GOOD)
		{
			/* certificate is good */
			ocsp_status = 0;
		}
		if (cst->type == V_OCSP_CERTSTATUS_REVOKED)
		{
			/* certificate is revoked */
			ocsp_status = 1;
		}
	}
	OCSP_BASICRESP_free(br);
	OCSP_RESPONSE_free(rsp);
	return 1;
}

char *lookup_pin(char *pin)
{
	/* lookup pin in database */
	/* trusted root certificates (20181216: mozilla bundle) */
	if (!strcmp(pin, "L8VmekuaJnjtasatJUZfy/YJS/zZUECXx6j6R63l6Ig="))       return "AC RAIZ FNMT-RCM (ES)";
	if (!strcmp(pin, "/YctF2YX5QwmYRnQ/bBHsHMtogSLEhr3uYYMo+Ly8r4="))       return "AC Ra??z Certic??mara S.A.";
	if (!strcmp(pin, "BVcK5usPzrQhDm23lIa3CUyvIAQB4Um2Z3RBtfJeRJs="))       return "ACCVRAIZ1 (ES)";
	if (!strcmp(pin, "JdSRPPWHCXQU0p0m9sGxlCzW1k6vRdD8+BUmrbqW0yQ="))       return "Actalis Authentication Root CA";
	if (!strcmp(pin, "lCppFqbkrlJ3EcVFAkeip0+44VaoJUymbnOaEUk7tEU="))       return "AddTrust External CA Root";
	if (!strcmp(pin, "BStocQfshOhzA4JFLsKidFF0XXSFpX1vRk4Np6G2ryo="))       return "AddTrust Class 1 CA Root";
	if (!strcmp(pin, "bEZLmlsjOl6HTadlwm8EUBDS3c/0V5TwtMfkqvpQFJU="))       return "AffirmTrust Commercial";
	if (!strcmp(pin, "lAcq0/WPcPkwmOWl9sBMlscQvYSdgxhJGa6Q64kK5AA="))       return "AffirmTrust Networking";
	if (!strcmp(pin, "x/Q7TPW3FWgpT4IrU3YmBfbd0Vyt7Oc56eLDy6YenWc="))       return "AffirmTrust Premium";
	if (!strcmp(pin, "MhmwkRT/SVo+tusAwu/qs0ACrl8KVsdnnqCHo/oDfk8="))       return "AffirmTrust Premium ECC";
	if (!strcmp(pin, "++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI="))       return "Amazon Root CA 1";
	if (!strcmp(pin, "f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE="))       return "Amazon Root CA 2";
	if (!strcmp(pin, "NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k="))       return "Amazon Root CA 3";
	if (!strcmp(pin, "9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U="))       return "Amazon Root CA 4";
	if (!strcmp(pin, "5co3vHtsNhl5vGsSPKmh2wGQRtf/X1ffuFSxnRCwaC8="))       return "Atos TrustedRoot 2011 (DE)";
	if (!strcmp(pin, "Ow1ztL5KhUrcPlHX75+kiu+7LN2CTWe9x9fQmiq8LUM="))       return "Autoridad de Certificacion Firmaprofesional CIF A62634068";
	if (!strcmp(pin, "Y9mvm0exBk1JoQ57f9Vm28jKo5lFm/woKcVxrYxu80o="))       return "Baltimore CyberTrust Root";
	if (!strcmp(pin, "WVWuKRV0qTE0LPdFDhZlLt4eD7MJfhVx36wRyRVgFWQ="))       return "Buypass Class 2 Root CA";
	if (!strcmp(pin, "sD2HsFbQjMnU5nXvGcqDq1NTIWioJYWYvnLm2Fx918E="))       return "Buypass Class 3 Root CA";
	if (!strcmp(pin, "cCEWzNi/I+FkZvDg26DtaiOanBzWqPWmazmvNZUCA4U="))       return "CA Disig Root R2";
	if (!strcmp(pin, "iir/vRocXRvcy7f1SLqZX5ZoBrP9DDoA+uLlLzyFOYk="))       return "Chambers of Commerce Root";
	if (!strcmp(pin, "Tq2ptTEecYGZ2Y6oK5UAXLqTGYqx+X78vo3GIBYo+K8="))       return "Global Chambersign Root";
	if (!strcmp(pin, "UQ0g5cR/Y89mayD2GvYrwJmkKsgk/6RDotp8kLGAipE="))       return "Certigna";
	if (!strcmp(pin, "axpQXgJG8vYMSQ/wwJenvichDLt1ACN/iLDNSCmLybg="))       return "Certinomis - Root CA";
	if (!strcmp(pin, "dy/Myn0WRtYGKBNP8ubn9boJWJi+WWmLzp0V+W9pqfM="))       return "Class 2 Primary CA";
	if (!strcmp(pin, "7JBW/pUJQRYJdjrugx7zfIMrdbPXJ1KPx8dSAcH/KOY="))       return "Certplus Root CA G1";
	if (!strcmp(pin, "U3VmJij6CmhArsjFkr9djeVk7T77YsfJMvyo11TZu9Y="))       return "Certplus Root CA G2";
	if (!strcmp(pin, "28HjoVI4oEg7zbj97GFuA+cFpI4qUBFXyt87nHMRxeU="))       return "certSIGN ROOT CA (RO)";
	if (!strcmp(pin, "lzasOyXRbEWkVBipZFeBVkgKjMQ0VB3cXdWSMyKYaN4="))       return "Certum CA";
	if (!strcmp(pin, "qiYwp7YXsE0KKUureoyqpQFubb5gSDeoOoVxn6tmfrU="))       return "Certum Trusted Network CA";
	if (!strcmp(pin, "aztX6eyI0bs9AWN/8zx2mLPJdYJV6fAeqRePPn87K1I="))       return "Certum Trusted Network CA 2";
	if (!strcmp(pin, "3V7RwJD59EgGG6qUprsRAXVE6e76ogzHFM5sYz9dxik="))       return "CFCA EV ROOT";
	if (!strcmp(pin, "ztQ5AqtftXtEIyLcDhcqT7VfcXi4CPlOeApv1sxr2Bg="))       return "Chambers of Commerce Root - 2008";
	if (!strcmp(pin, "vRU+17BDT2iGsXvOi76E7TQMcTLXAqj0+jGPdW7L1vM="))       return "AAA Certificate Services";
	if (!strcmp(pin, "AG1751Vd2CAmRCxPGieoDomhmJy4ezREjtIZTBgZbV4="))       return "COMODO Certification Authority";
	if (!strcmp(pin, "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU="))       return "COMODO ECC Certification Authority";
	if (!strcmp(pin, "grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME="))       return "COMODO RSA Certification Authority";
	if (!strcmp(pin, "foeCwVDOOVL4AuY2AjpdPpW7XWjjPoWtsroXgSXOvxU="))       return "Cybertrust Global Root";
	if (!strcmp(pin, "1JxvKJzQVlGUkkgPGS8Apvx8GGLasue12OBfZnj64UE="))       return "D-TRUST Root CA 3 2013";
	if (!strcmp(pin, "7KDxgUAs56hlKzG00DbfJH46MLf0GlDZHsT5CwBrQ6E="))       return "D-TRUST Root Class 3 CA 2 2009";
	if (!strcmp(pin, "/zQvtsTIvTCkcG9zSJU58Z5uSMwF9GJUZU9mENvFQOk="))       return "D-TRUST Root Class 3 CA 2 EV 2009";
	if (!strcmp(pin, "0d4q5hyN8vpiOWYWPUxz1GC/xCjldYW+a/65pWMj0bY="))       return "Deutsche Telekom Root CA 2";
	if (!strcmp(pin, "I/Lt/z7ekCWanjD0Cvj5EqXls2lOaThEA0H2Bg4BT/o="))       return "DigiCert Assured ID Root CA";
	if (!strcmp(pin, "8ca6Zwz8iOTfUpc8rkIPCgid1HQUT+WAbEIAZOFZEik="))       return "DigiCert Assured ID Root G2";
	if (!strcmp(pin, "Fe7TOVlLME+M+Ee0dzcdjW/sYfTbKwGvWJ58U7Ncrkw="))       return "DigiCert Assured ID Root G3";
	if (!strcmp(pin, "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="))       return "DigiCert Global Root CA";
	if (!strcmp(pin, "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY="))       return "DigiCert Global Root G2";
	if (!strcmp(pin, "uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc="))       return "DigiCert Global Root G3";
	if (!strcmp(pin, "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="))       return "DigiCert High Assurance EV Root CA";
	if (!strcmp(pin, "Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNkcpw="))       return "DigiCert Trusted Root G4";
	if (!strcmp(pin, "Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys="))       return "DST Root CA X3";
	if (!strcmp(pin, "wa0bGJjsOVBI3wcL+iF+JckTvtjKa3PeCFUohGoBA8E="))       return "E-Tugra Certification Authority";
	if (!strcmp(pin, "sh0qdDMYcSuhbzmRnZYaS6+6O8qaQ6dbH8/iLF1wyro="))       return "EC-ACC";
	if (!strcmp(pin, "VhdNOtlxqJRJZLGJgR8wCEk6apBCLjxYBOyDjU+U9iI="))       return "EE Certification Centre Root CA, emailAddress = pki@sk.ee";
	if (!strcmp(pin, "bb+uANN7nNc/j7R95lkXrwDg3d9C286sIMF8AnXuIJU="))       return "Entrust Root Certification Authority";
	if (!strcmp(pin, "/qK31kX7pz11PB7Jp4cMQOH3sMVh6Se5hb9xGGbjbyI="))       return "Entrust Root Certification Authority - EC1";
	if (!strcmp(pin, "du6FkDdMcVQ3u8prumAo6t3i3G27uMP2EOhR8R0at/U="))       return "Entrust Root Certification Authority - G2";
	if (!strcmp(pin, "HqPF5D7WbC2imDpCpKebHpBnhs6fG1hiFBmgBGOofTg="))       return "Entrust.net Certification Authority (2048)";
	if (!strcmp(pin, "YlVMFwBVQ7I3IV8EJo3NL9HEcCQK08hmDiWuLFljD1U="))       return "ePKI Root Certification Authority (Chunghwa Telecom, TW)";
	if (!strcmp(pin, "zrGUEcZQUsdX+UHrgmyWlB5NCNCWx9t+fqPE+ME/GhM="))       return "GDCA TrustAUTH R5 ROOT";
	if (!strcmp(pin, "h6801m+z8v3zbgkRHpq6L29Esgfzhj89C1SyUCOQmqU="))       return "GeoTrust Global CA";
	if (!strcmp(pin, "SQVGZiOrQXi+kqxcvWWE96HhfydlLVqFr4lQTqI5qqo="))       return "GeoTrust Primary Certification Authority";
	if (!strcmp(pin, "vPtEqrmtAhAVcGtBIep2HIHJ6IlnWQ9vlK50TciLePs="))       return "GeoTrust Primary Certification Authority - G2";
	if (!strcmp(pin, "q5hJUnat8eyv8o81xTBIeB5cFxjaucjmelBPT2pRMo8="))       return "GeoTrust Primary Certification Authority - G3";
	if (!strcmp(pin, "lpkiXF3lLlbN0y3y6W0c/qWqPKC7Us2JM8I7XCdEOCA="))       return "GeoTrust Universal CA";
	if (!strcmp(pin, "fKoDRlEkWQxgHlZ+UhSOlSwM/+iQAFMP4NlbbVDqrkE="))       return "GeoTrust Universal CA 2";
	if (!strcmp(pin, "knobhWIoBXbQSMUDIa2kPYcD0tlSGhjCi4xGzGquTv0="))       return "Global Chambersign Root - 2008";
	if (!strcmp(pin, "CLOmM1/OXvSPjw5UOYbAf9GKOxImEp9hhku9W90fHMk="))       return "GlobalSign";
	if (!strcmp(pin, "fg6tdrtoGdwvVFEahDVPboswe53YIFjqbABPAdndpd8="))       return "GlobalSign";
	if (!strcmp(pin, "K87oWBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q="))       return "GlobalSign Root CA";
	if (!strcmp(pin, "iie1VXtL7HzAMF+/PVPR9xzT80kQxdZeJ+zduCB3uj0="))       return "GlobalSign";
	if (!strcmp(pin, "cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A="))       return "GlobalSign";
	if (!strcmp(pin, "aCdH+LpiG4fN07wpXtXKvOciocDANj0daLOJKNJ4fx4="))       return "GlobalSign";
	if (!strcmp(pin, "VjLZe/p3W/PJnd6lL8JVNBCGQBZynFLdZSTIqcO0SJ8="))       return "Go Daddy Class 2 Certification Authority";
	if (!strcmp(pin, "Ko8tivDrEjiY90yGasP6ZpBU4jwXvHqVvQI0GS3GNdA="))       return "Go Daddy Root Certificate Authority - G2";
	if (!strcmp(pin, "u1IIbQY56NszJ3Wsj06ENdks6wD04k8o/A6r4kB3LoA="))       return "Hellenic Academic and Research Institutions ECC RootCA 2015";
	if (!strcmp(pin, "Gno6GmjdI2Hj87uFXzsm/NiLGX2N1N4Gzxs2KsiewTs="))       return "Hellenic Academic and Research Institutions RootCA 2011";
	if (!strcmp(pin, "UMyGupbbMmPHmkPq0HVT2fVmWeaQfnLYwCZjehzchdw="))       return "Hellenic Academic and Research Institutions RootCA 2015";
	if (!strcmp(pin, "NsIjFBMaX78bcOpMz0vBOnd9k47GXh2iTjws/QHT0WM="))       return "Hongkong Post Root CA 1";
	if (!strcmp(pin, "B+hU8mp8vTiZJ6oEG/7xts0h3RQ4GK2UfcZVqeWH/og="))       return "IdenTrust Commercial Root CA 1";
	if (!strcmp(pin, "WN1h/rNup9JYckNxcJFJyxITN4ZMrLLQmZrSBznQZHc="))       return "IdenTrust Public Sector Root CA 1";
	if (!strcmp(pin, "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="))       return "ISRG Root X1";
	if (!strcmp(pin, "lSwgOcAkPrUV3XPYP8NkMYSHT+sIYqmDdzHtm0dC4Xo="))       return "Izenpe.com";
	if (!strcmp(pin, "tzgpDMCFR+eaxn+DHrszVHxOfbRRTi0piMI8RBNA60E="))       return "LuxTrust Global Root 2";
	if (!strcmp(pin, "YWFnIBQzrqbI5eMHCvyvZ0kYj4FL0auxea6NrTq/Juw="))       return "Microsec e-Szigno Root CA 2009, emailAddress = info@e-szigno.hu";
	if (!strcmp(pin, "9Iut199qBmkNCuMTc7EoVfje2xRRfzYqMTEBzJjMazU="))       return "NetLock Arany (Class Gold) F??tan??s??tv??ny";
	if (!strcmp(pin, "MtGA7THJNVieydu7ciEjuIO1/C3BD5/KOpXXfhv8tTQ="))       return "Network Solutions Certificate Authority";
	if (!strcmp(pin, "ziTrBibe/YFoyWp3AfCTAWAP5d0NvOWOnJe4MK8C7yg="))       return "OISTE WISeKey Global Root GA CA";
	if (!strcmp(pin, "FJ8u5juaXlgDJAp3DcmR/C40ReYoMcJFpJvE8fc4/5w="))       return "OISTE WISeKey Global Root GB CA";
	if (!strcmp(pin, "/Tcb6pdV/2DIgoyEm45SFd5TLWGwCYVfoK1jDZDu+C4="))       return "OISTE WISeKey Global Root GC CA";
	if (!strcmp(pin, "bW8MNAlxohijHRAzDqmufHplUFNMbu/t3SEY4RTbRz4="))       return "OpenTrust Root CA G1";
	if (!strcmp(pin, "Z1YF8VZ+JfvSUmvv6irvvbInnz4bqjowOudVXRvaPuQ="))       return "OpenTrust Root CA G2";
	if (!strcmp(pin, "iR/4mOSo1VUUAFbjF27qkfTYCO5/bRv7zOb4SAdjn5E="))       return "OpenTrust Root CA G3";
	if (!strcmp(pin, "vj23t5v+V53PmwfKTK11r/FpdVaOW0XPyuTWH7Yxdag="))       return "QuoVadis Root Certification Authority";
	if (!strcmp(pin, "hqaPBQA0EmpUDTnbLF+RfvZqlPuWGfoezYJ86ka6DLA="))       return "QuoVadis Root CA 1 G3";
	if (!strcmp(pin, "j9ESw8g3DxR9XM06fYZeuN1UB4O6xp/GAIjjdD/zM3g="))       return "QuoVadis Root CA 2";
	if (!strcmp(pin, "SkntvS+PgjC9VZKzE1c/4cFypF+pgBHMHt27Nq3j/OU="))       return "QuoVadis Root CA 2 G3";
	if (!strcmp(pin, "DHrKpxAiZyC7yUA0nuLmFIZSqJ2/QGojLIlfbceOu5o="))       return "QuoVadis Root CA 3";
	if (!strcmp(pin, "80OOI7POUyUi+s8weSP1j9GGCOm6et3DDpUrQ8SWFsM="))       return "QuoVadis Root CA 3 G3";
	if (!strcmp(pin, "JZaQTcTWma4gws703OR/KFk313RkrDcHRvUt6na6DCg="))       return "Secure Global CA";
	if (!strcmp(pin, "u0Eo7JYg8tKknOjixOJXrrrZOg8RxWtfpLAOI3Wfo50="))       return "SecureSign RootCA11";
	if (!strcmp(pin, "dykHF2FLJfEpZOvbOLX4PKrcD2w2sHd/iA/G3uHTOcw="))       return "SecureTrust CA";
	if (!strcmp(pin, "KkISYFqj6K7LD8GYBs87QLU7lfGjTbvW4+0nIwMkq7M="))       return "Security Communication RootCA1 (JP)";
	if (!strcmp(pin, "M4BwmvOwlr48wqQFSBQsClIAKNsJ4st3riIGYWq2y7Q="))       return "Security Communication RootCA2 (JP)";
	if (!strcmp(pin, "0qXzLw4BuRDvTjtGv4Tlr1+1aJ59FQfpKeNorIjGzHY="))       return "Sonera Class2 CA";
	if (!strcmp(pin, "NIdnza073SiyuN1TUa7DDGjOxc1p0nbfOCfbxPWAZGQ="))       return "SSL.com EV Root Certification Authority ECC";
	if (!strcmp(pin, "fNZ8JI9p2D/C+bsB3LH3rWejY9BGBDeW0JhMOiMfa7A="))       return "SSL.com EV Root Certification Authority RSA R2";
	if (!strcmp(pin, "oyD01TTXvpfBro3QSZc1vIlcMjrdLTiL/M9mLCPX+Zo="))       return "SSL.com Root Certification Authority ECC";
	if (!strcmp(pin, "0cRTd+vc1hjNFlHcLgLCHXUeWqn80bNDH/bs9qMTSPo="))       return "SSL.com Root Certification Authority RSA";
	if (!strcmp(pin, "lR7gRvqDMW5nhsCMRPE7TKLq0tJkTWMxQ5HAzHCIfQ0="))       return "Staat der Nederlanden EV Root CA";
	if (!strcmp(pin, "Bed+8f3+BeLcpSLK5k2DeaBBt7TxbHyuNgZ6f3KhSHI="))       return "Staat der Nederlanden Root CA - G2";
	if (!strcmp(pin, "QiOJQAOogcXfa6sWPbI1wiGhjVS/dZlFgg5nDaguPzk="))       return "Staat der Nederlanden Root CA - G3";
	if (!strcmp(pin, "FfFKxFycfaIz00eRZOgTf+Ne4POK6FgYPwhBDqgqxLQ="))       return "Starfield Class 2 Certification Authority (US)";
	if (!strcmp(pin, "gI1os/q0iEpflxrOfRBVDXqVoWN3Tz7Dav/7IT++THQ="))       return "Starfield Root Certificate Authority - G2";
	if (!strcmp(pin, "KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I="))       return "Starfield Services Root Certificate Authority - G2";
	if (!strcmp(pin, "y26RcRrW1VyJBvN5ywcftcR5M2VKdBVhLu5mKfJvvNc="))       return "Swisscom Root CA 2";
	if (!strcmp(pin, "QPz8KIddzL/ry99s10MzEtpjxO/PO9extQXCICCuAnQ="))       return "SwissSign Gold CA - G2";
	if (!strcmp(pin, "KovtMq5oDS0Ye5p6/Rcdg/0Lk16vniwbQ+gCeNIGPjk="))       return "SwissSign Platinum CA - G2";
	if (!strcmp(pin, "kxgib4yDr+R/X0fCT1nOEtuoxzsYG+5rLqH0Cga8GGk="))       return "SwissSign Silver CA - G2";
	if (!strcmp(pin, "MVEmgCM/XyofKUN/VtSYjPCvxBzGxdpidZKOnAvq3ic="))       return "Symantec Class 1 Public Primary Certification Authority - G4";
	if (!strcmp(pin, "0vkaBOOmHU6teEjI1DteEVLYhXJ0ibxlc4tnwKInhac="))       return "Symantec Class 1 Public Primary Certification Authority - G6";
	if (!strcmp(pin, "MCeimPpXMU3A490QGUEbj0BMQ8P5NM4734VlEsgKoVw="))       return "Symantec Class 2 Public Primary Certification Authority - G4";
	if (!strcmp(pin, "ryB8Yf2cfPksKv6BVCgtw/LL8y91zRcoFMUrA7frwlg="))       return "Symantec Class 2 Public Primary Certification Authority - G6";
	if (!strcmp(pin, "bjZLYTPe79y7ISc8X0RaIK+8BQONWwIcDCFTA5AWNFs="))       return "SZAFIR ROOT CA2";
	if (!strcmp(pin, "YQbA46CimYMYdRJ719PMGFmAPVEcrBHrbghA3RZvwQ4="))       return "T-TeleSec GlobalRoot Class 2";
	if (!strcmp(pin, "jXZ3ZLPL2giSnQcqIqVh9NzdG8V9PL3clIxH0rR/kSI="))       return "T-TeleSec GlobalRoot Class 3";
	if (!strcmp(pin, "qBKTRF2xlqIDD55FX+PHSppPgxewKwFAYCeocIF0Q0w="))       return "Government Root Certification Authority (TW)";
	if (!strcmp(pin, "ELo0hcqLtogKuVMaQGPkABVVVhx/LgVRZfSbLXT8X2s="))       return "TeliaSonera Root CA v1";
	if (!strcmp(pin, "HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY="))       return "thawte Primary Root CA";
	if (!strcmp(pin, "Z9xPMvoQ59AaeaBzqgyeAhLsL/w9d54Kp/nA8OHCyJM="))       return "thawte Primary Root CA - G2";
	if (!strcmp(pin, "GQbGEk27Q4V40A4GbVBUxsN/D6YCjAVUXgmU7drshik="))       return "thawte Primary Root CA - G3";
	if (!strcmp(pin, "ev5LBxovH0b4upRKJtWE1ZYLkvtIw7obfKuEkF8yqs0="))       return "TrustCor ECA-1";
	if (!strcmp(pin, "6of0Yt7v/713daoqS34Py5HCLu5t9p7ZAQDMxzsxFHY="))       return "TrustCor RootCert CA-1";
	if (!strcmp(pin, "xj1oxkihi3dkHEJ6Zp1hyXaKVfT80DIurJbFdwApnPE="))       return "TrustCor RootCert CA-2";
	if (!strcmp(pin, "qHRDs9iW6yV8zOmbla2pvIG5204xQqqama8JQssKSjo="))       return "Trustis FPS Root CA (GB)";
	if (!strcmp(pin, "VeAL4nfOsFRSmfJP2fh34qzzKFLbQ//NKbynSzm0yfo="))       return "TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1";
	if (!strcmp(pin, "xES1tmzl1x4bXkDyc4XJXL/SSgW1b3DKwJkvD1DDN5w="))       return "TWCA Global Root CA";
	if (!strcmp(pin, "ksRoeWJu8swezqUMcvteOFhECV8hy/Oyg8uC5rn8alg="))       return "TWCA Root Certification Authority";
	if (!strcmp(pin, "ICGRfpgmOUXIWcQ/HXPLQTkFPEFPoDyjvH7ohhQpjzs="))       return "USERTrust ECC Certification Authority";
	if (!strcmp(pin, "x4QzPSC810K5/cMjb05Qm4k3Bw5zBn4lTdO/nEW/Td4="))       return "USERTrust RSA Certification Authority";
	if (!strcmp(pin, "Laj56jRU0hFGRko/nQKNxMf7tXscUsc8KwVyovWZotM="))       return "UTN-USERFirst-Client Authentication and Email";
	if (!strcmp(pin, "IgduWu9Eu5pBaii30cRDItcFn2D+/6XK9sW+hEeJEwM="))       return "VeriSign Class 1 Public Primary Certification Authority - G3";
	if (!strcmp(pin, "cAajgxHlj7GTSEIzIYIQxmEloOSoJq7VOaxWHfv72QM="))       return "VeriSign Class 2 Public Primary Certification Authority - G3";
	if (!strcmp(pin, "SVqWumuteCQHvVIaALrOZXuzVVVeS7f4FGxxu6V+es4="))       return "VeriSign Class 3 Public Primary Certification Authority - G3";
	if (!strcmp(pin, "UZJDjsNp1+4M5x9cbbdflB779y5YRBcV6Z6rBMLIrO4="))       return "VeriSign Class 3 Public Primary Certification Authority - G4";
	if (!strcmp(pin, "JbQbUG5JMJUoI6brnx0x3vZF6jilxsapbXGVfjhN8Fg="))       return "VeriSign Class 3 Public Primary Certification Authority - G5";
	if (!strcmp(pin, "lnsM2T/O9/J84sJFdnrpsFp3awZJ+ZZbYpCWhGloaHI="))       return "VeriSign Universal Root Certification Authority";
	if (!strcmp(pin, "BRz5+pXkDpuD7a7aaWH2Fox4ecRmAXJHnN1RqwPOpis="))       return "XRamp Global Certification Authority";
	/* common intermediate certificates */
	if (!strcmp(pin, "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="))	return "Let's Encrypt Authority X3";
	if (!strcmp(pin, "sRHdihwgkaib1P1gxX8HFszlD+7/gTfNvuAybgLPNis="))	return "Let's Encrypt Authority X4";
	if (!strcmp(pin, "nKWcsYrc+y5I8vLf1VGByjbt+Hnasjl+9h8lNKJytoE="))	return "RapidSSL RSA CA 2018";
	if (!strcmp(pin, "E3tYcwo9CiqATmKtpMLW5V+pzIq+ZoDmpXSiJlXGmTo="))	return "RapidSSL TLS RSA CA G1";
	if (!strcmp(pin, "f8NnEFZxQ4ExFOhSN7EiFWtiudZQVD2oY60uauV/n78="))	return "Google Internet Authority G3";
	if (!strcmp(pin, "njN4rRG+22dNXAi+yb8e3UMypgzPUPHlv4+foULwl1g="))	return "DigiCert Global CA G2";
	if (!strcmp(pin, "wUY9EOTJmS7Aj4fDVCu/KeE++mV7FgIcbn4WhMz1I2k="))	return "Microsoft IT TLS CA 4";
	if (!strcmp(pin, "k2v657xBsOVe1PQRwOsHsw3bsGT2VzIqz5K+59sNQws="))	return "DigiCert SHA2 High Assurance Server CA";
	if (!strcmp(pin, "8Rw90Ej3Ttt8RRkrg+WYDS9n7IS03bk5bjP/UXPtaY8="))	return "Go Daddy Secure Certificate Authority - G2";
	if (!strcmp(pin, "WOINGBsGlG95B7s/6U7XB/KM7U73y+sXgtLqZpn3G88="))	return "DigiCert ECC Extended Validation Server CA";
	if (!strcmp(pin, "3kcNJzkUJ1RqMXJzFX4Zxux5WfETK+uL6Viq9lJNn4o="))	return "CloudFlare Inc ECC CA-2";
	return NULL;
}

void ShowUsage(char *cmd)
{
	fprintf(stderr, "Usage: %s [-h] [-starttls <type>] [-sni <hostname>] [-min <1.0|1.1|1.2|1.3>] <hostname> [port]\n", cmd);
	fprintf(stderr, "\n");
	fprintf(stderr, "\t-h\t\t\t\tShow this help\n");
	fprintf(stderr, "\t-starttls <type>\tUse STARTTLS for <type> of service (ftp imap pop3 smtp)\n");
	fprintf(stderr, "\t-sni <hostname>\tUse <hostname> for SNI negotiation (useful to test certs on IPs that are not live yet)\n");
	fprintf(stderr, "\t-min <1.0|1.1|1.2|1.3>\tSet minimum supported TLS version\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "<hostname> is mandatory and can be a FQDN or IP address\n");
	fprintf(stderr, "[port] is optional, and defaults to 443 if omitted.\n\n");
	fprintf(stderr, "Examples:\n");
	fprintf(stderr, "\t%s mail.dan.me.uk 465\n", cmd);
	fprintf(stderr, "\t%s mail.dan.me.uk\n", cmd);
	fprintf(stderr, "\t%s -sni www.dan.me.uk 192.168.0.1 443\n", cmd);
	fprintf(stderr, "\t%s -min 1.2 www.dan.me.uk 443\n", cmd);
	fprintf(stderr, "\nSVN version: $Id: sslinfo.c 1061 2023-11-27 16:04:19Z dan $\n");
	exit(0);
}

void starttls_readline(int sd, char *buf)
{
	char	ch, *s;
	int	c = 0;

	s = buf;
	while (read(sd, &ch, 1)==1)
	{
		if (ch == '\r') continue;
		if (ch == '\n')
		{
			*s++ = '\0';
			return;
		}
		*s++ = ch;
		c++;
		if (c>1023)
		{
			*s++ = '\0';
			return;
		}
	}
}

void starttls_negotiate(int starttls_svc, int sd, char *buf)
{
	struct utsname	uname_data;

	uname(&uname_data);

	/* need to negotiate non-SSL first */
	switch (starttls_svc) {
		case 1:		/* smtp */
				starttls_readline(sd, buf);
				if (strncmp(buf, "220", 3) == 0)
				{
					snprintf(buf, 512, "EHLO %s\r\n", uname_data.nodename);
					write(sd, buf, strlen(buf));
					while (strncmp(buf, "250 ", 4) != 0)
						starttls_readline(sd, buf);
					write(sd, "STARTTLS\r\n", 10);
					while (strncmp(buf, "220 ", 4) != 0)
						starttls_readline(sd, buf);
				}
				break;
		case 2:		/* imap */
				starttls_readline(sd, buf);
				if (strncmp(buf, "* OK", 4) == 0)
				{
					write(sd, "a STARTTLS\r\n", 12);
					starttls_readline(sd, buf);
				}
				break;
		case 3:		/* pop3 */
				starttls_readline(sd, buf);
				if (strncmp(buf, "+OK ", 4) == 0)
				{
					write(sd, "STLS\r\n", 6);
					starttls_readline(sd, buf);
				}
				break;
		case 4:		/* ftp */
				starttls_readline(sd, buf);
				if (strncmp(buf, "220 ", 4) == 0)
				{
					write(sd, "AUTH TLS\r\n", 10);
					starttls_readline(sd, buf);
				}
				break;
	}
	return;
}

void timeout_handler(int signum)
{
	printf("ERROR: timeout\n");
	exit(1);
}

unsigned char *create_pkp(X509 *server_cert, unsigned char *hash)
{
	unsigned int		len;
	unsigned char		*buf = NULL;
	unsigned char		tmp_dgst[EVP_MAX_MD_SIZE];

	len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(server_cert), &buf);
	EVP_Q_digest(NULL, "SHA256", NULL, buf, len, tmp_dgst, NULL);
	OPENSSL_free(buf);
	EVP_EncodeBlock((unsigned char *)hash, tmp_dgst, SHA256_DIGEST_LENGTH);

	return hash;
}

char *match_pkp(char *pkp, SSL *ssl)
{
	/* if public key pin matches, return subject - otherwise return null */
	STACK_OF(X509)			*sk;
	int				i;
	unsigned char			temp_pin[256];
	unsigned char			*s;
	char				*str, *str2;

	sk = SSL_get_peer_cert_chain(ssl);
	if (!sk)
		return NULL;
	for (i=0; i<sk_X509_num(sk); i++)
	{
		s = create_pkp(sk_X509_value(sk, i), temp_pin);
		if (s && (strcmp(pkp, (char *)s) == 0))
		{
			str = X509_NAME_oneline(X509_get_subject_name(sk_X509_value(sk, i)),0,0);
			str2 = strstr(str, "CN=");
			if (str2)
			{
				str2 +=3;
				return str2;
			} else 
				return str;
		}
	}
	return NULL;
}

int main (int argc, char **argv)
{
#ifndef OPENSSL_NO_EC
	unsigned char			curve[64];
#endif
	int				pday, psec;
	int				i, err;
	int				sd;
	char				hostname[255];
	char				sni_hostname[255];
	int				port;
	long				ssl_opts = 0;
	struct sigaction		sigact;
	struct itimerval		timer;
	struct sockaddr_in		sa;
	struct sockaddr_in6		sa6;
	struct hostent			*hp;
	char				ipaddr[INET6_ADDRSTRLEN];
	SSL_CTX 			*ctx;
	SSL     			*ssl;
	X509    			*server_cert;
	char    			*str, *str2;
	char				*s, *t;
	unsigned char			*us;
	SSL_METHOD			*meth;
	EVP_PKEY			*pktmp;
	const COMP_METHOD		*comp, *expansion;
	char				alg[256];
	bool				flag_verified = true;
	bool				flag_starttls = false;
	int				starttls_svc = 0;
	char				buf[1024];
	char				tmp[1024];
	int				len1, len2;
	GENERAL_NAMES			*names = NULL;
	GENERAL_NAME			*entry = NULL;
	unsigned char			*utf8 = NULL;
	ASN1_INTEGER			*bs;
	unsigned char			pkpin[256];
	STACK_OF(X509)			*sk;

	stderr = stdout;

	port = 0;
	hostname[0] = '\0';
	sni_hostname[0] = '\0';
	/* parse cmdline options */
	for (i=1; i<argc; i++)
	{
		if (argv[i][0] == '-')
		{
			/* options */
			if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
				ShowUsage(argv[0]);
			if ((strcmp(argv[i], "-s") == 0) || (strcmp(argv[i], "-starttls") == 0) || (strcmp(argv[i], "--starttls") == 0))
			{
				flag_starttls = true;
				i++;
				if (i == argc)
				{
					fprintf(stderr, "ERROR: You must specify the STARTTLS service to use - see help.\n");
					exit(1);
				}
				if (strcmp(argv[i], "ftp") == 0)
				{
					starttls_svc = 4;
					continue;
				}
				if ((strcmp(argv[i], "imap") == 0) || (strcmp(argv[i], "imap4") == 0))
				{
					starttls_svc = 2;
					continue;
				}
				if ((strcmp(argv[i], "pop") == 0) || (strcmp(argv[i], "pop3") == 0))
				{
					starttls_svc = 3;
					continue;
				}
				if (strcmp(argv[i], "smtp") == 0)
				{
					starttls_svc = 1;
					continue;
				}
				fprintf(stderr, "ERROR: Unknown STARTTLS service - see help for supported STARTTLS mechanisms.\n");
				exit(1);
			}
			if (strcmp(argv[i], "-sni") == 0)
			{
				i++;
				if (i == argc)
				{
					fprintf(stderr, "ERROR: You must specify the SNI hostname to use - see help.\n");
					exit(1);
				}
				strncpy(sni_hostname, argv[i], sizeof(sni_hostname));
				continue;
			}
			if (strcmp(argv[i], "-min") == 0)
			{
				i++;
				if (i == argc)
				{
					fprintf(stderr, "ERROR: You must specify the minimum TLS version supported - see help.\n");
					exit(1);
				}
				if (strcmp(argv[i], "1.0") == 0)
					continue;
				if (strcmp(argv[i], "1.1") == 0)
				{
					ssl_opts += SSL_OP_NO_TLSv1;
					continue;
				}
				if (strcmp(argv[i], "1.2") == 0)
				{
					ssl_opts += SSL_OP_NO_TLSv1;
					ssl_opts += SSL_OP_NO_TLSv1_1;
					continue;
				}
				if (strcmp(argv[i], "1.3") == 0)
				{
					ssl_opts += SSL_OP_NO_TLSv1;
					ssl_opts += SSL_OP_NO_TLSv1_1;
					ssl_opts += SSL_OP_NO_TLSv1_2;
					continue;
				}
				fprintf(stderr, "ERROR: unknown minimum TLS version - see help.\n");
				exit(1);
			}
			/* unknown option */
			fprintf(stderr, "ERROR: Unknown option (%s) - see '%s -h' for usage\n", argv[i], argv[0]);
			exit(1);
		} else {
			if (hostname[0] == '\0')
			{
				strncpy(hostname, argv[i], sizeof(hostname));
				continue;
			}
			if (port == 0)
			{
				port = atoi(argv[i]);
				continue;
			}
			/* extra options? */
			fprintf(stderr, "ERROR: Extra command line option(%s) - see '%s -h' for usage\n", argv[i], argv[0]);
			exit(1);
		}
	}

	if (hostname[0] == '\0')
		ShowUsage(argv[0]);

	if (sni_hostname[0] == '\0')
		strncpy(sni_hostname, hostname, sizeof(sni_hostname));

	/* default port to 443 if not specified */
	if (port == 0)
		port = 443;
	err = 0;

	/* setup timeout timer */
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = &timeout_handler;
	sigaction(SIGALRM, &sigact, NULL);

	/* expire after 20 seconds */
	timer.it_value.tv_sec = 20;
	timer.it_value.tv_usec = 0;
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &timer, NULL);

	SSL_load_error_strings();
	SSL_library_init();
	meth = (SSL_METHOD *)TLS_client_method();
	ctx = SSL_CTX_new (meth);
	CHK_NULL(ctx);
	CHK_SSL(err);
	/* set our options */
	/* default, try TLSv1.0 and above only */
	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE | SSL_OP_NO_SSLv2 |
		SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION |
		SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
	if (ssl_opts != 0)
		SSL_CTX_set_options(ctx, ssl_opts);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 9);
	err = SSL_CTX_load_verify_locations(ctx, "/etc/ssl/cert.pem", NULL);
  
	memset (&sa, '\0', sizeof(sa));
	/* lookup ip - try IPv6 first */
	if ((hp = gethostbyname2(hostname, AF_INET6)) == NULL)
	{
		/* try IPv4 */
		if ((hp = gethostbyname2(hostname, AF_INET)) == NULL)
		{
			exit(1);
		} else {
			sd = socket(AF_INET, SOCK_STREAM, 0);
			CHK_ERR(sd, "ERROR: socket");

			bcopy(hp->h_addr_list[0], (char *) &sa.sin_addr, hp->h_length);
			sa.sin_family = AF_INET;
			sa.sin_port = htons(port);

			inet_ntop(AF_INET, &(sa.sin_addr), ipaddr, INET_ADDRSTRLEN);

			err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
			CHK_ERR(err, "ERROR: connect");
			if (flag_starttls)
				starttls_negotiate(starttls_svc, sd, buf);
		}
	} else {
		sd = socket(AF_INET6, SOCK_STREAM, 0);
		CHK_ERR(sd, "ERROR: socket");

		bcopy(hp->h_addr_list[0], (char *) &sa6.sin6_addr, hp->h_length);
		sa6.sin6_family = AF_INET6;
		sa6.sin6_port = htons(port);

		inet_ntop(AF_INET6, &(sa6.sin6_addr), ipaddr, INET6_ADDRSTRLEN);

		err = connect(sd, (struct sockaddr*) &sa6, sizeof(sa6));
		CHK_ERR(err, "ERROR: connect");
		if (flag_starttls)
			starttls_negotiate(starttls_svc, sd, buf);
	}
  
	ssl = SSL_new(ctx);
	CHK_NULL(ssl);    
	SSL_set_fd(ssl, sd);
	/* try to set hostname for SNI */
	err = SSL_set_tlsext_host_name(ssl, sni_hostname);
	/* setup OCSP handling */
	SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
	SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb);
	SSL_CTX_set_tlsext_status_arg(ctx, NULL);

	err = SSL_connect(ssl);
        if ((err) == -1)
        {
		/* certificate verify failed */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_verify_depth(ctx, 0);
		/* need to re-setup SSL from CTX */
		SSL_free(ssl);
		close(sd);
		if ((hp = gethostbyname2(hostname, AF_INET6)) == NULL)
		{
			sd = socket(AF_INET, SOCK_STREAM, 0);
			err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
		} else {
			sd = socket(AF_INET6, SOCK_STREAM, 0);
			err = connect(sd, (struct sockaddr*) &sa6, sizeof(sa6));
		}
		CHK_ERR(err, "ERROR: connect (2)");
		ssl = SSL_new(ctx);
		CHK_NULL(ssl);
		SSL_set_fd(ssl, sd);
		/* try to set hostname for SNI */
		err = SSL_set_tlsext_host_name(ssl, sni_hostname);
		err = SSL_connect(ssl);
		if ((err) == -1)
		{
			printf("ERROR: unable to connect.\n");
			exit(1);
		}
		flag_verified = false;
		if (flag_starttls)
			starttls_negotiate(starttls_svc, sd, buf);
		CHK_SSL(err);
        }

	printf("svn_id: $Id: sslinfo.c 1061 2023-11-27 16:04:19Z dan $\n");
	printf("header_version: %s\nlibrary_version: %s\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
	printf("ip_address: %s\n", ipaddr);
	printf("port: %d\n", port);
	if (flag_starttls)
	{
		printf("starttls: YES (");
		switch (starttls_svc) {
			case 1:		printf("smtp");		break;
			case 2:		printf("imap");		break;
			case 3:		printf("pop3");		break;
			case 4:		printf("ftp");		break;
		}
		printf(")\n");
	} else {
		printf("starttls: NO\n");
	}
	printf("sni_hostname: %s\n", sni_hostname);
	if (ocsp_status == 0)
		printf("ocsp_status: good\n");
	if (ocsp_status == 1)
		printf("ocsp_status: revoked\n");
	if (ocsp_status == -1)
		printf("ocsp_status: server does not support OCSP stapling\n");
	printf("version: %s\n", SSL_get_version(ssl));
	printf("cipher: %s\n", SSL_get_cipher (ssl));
  
	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);

	err = SSL_get_verify_result(ssl);
	if (!(X509_V_OK == err))
		printf("chain: incomplete (%ul)\n", err);
	else
		printf("chain: complete\n");

	/* show certificate chain */
	sk = SSL_get_peer_cert_chain(ssl);
	us = (unsigned char *)buf;
	for (i=0; i<sk_X509_num(sk); i++)
	{
		s = (char *)create_pkp(sk_X509_value(sk, i), us);
		printf("chain_%d: %s", i, s);
		str = X509_NAME_oneline(X509_get_subject_name(sk_X509_value(sk, i)),0,0);
		str2 = strstr(str, "CN=");
		if (str2)
		{
			str2 += 3;
			printf(" %s\n", str2);
		} else {
			printf(" %s\n", str);
		}
	}
  
	str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
	CHK_NULL(str);
	s = str;
	if (!strncmp(s, "/CN=", 4))
		s += 4;
	printf("subject: %s\n", s);
	OPENSSL_free(str);

	/* get SANs and display them (if present) */
	names = X509_get_ext_d2i(server_cert, NID_subject_alt_name, 0, 0);
	if (names)
	{
		/* we have some SANs */
		for (i=0; i<sk_GENERAL_NAME_num(names); i++)
		{
			entry = sk_GENERAL_NAME_value(names, i);
			if (!entry)
				continue;
			if (entry->type == GEN_DNS)
			{
				/* only interested in 'dns' types */
				len2 = -1;
				len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
				if (utf8)
					len2 = (int)strlen((const char*)utf8);
				if (len1 != len2)
				{
					/* this should never happen, but is a security safety feature */
					continue;
				}
				if (utf8)
				{
					printf("alt-subject: %s\n", utf8);
					OPENSSL_free(utf8);
					utf8 = NULL;
				}
			}
		}
	}

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
	CHK_NULL(str);
	s = strstr(str, "/CN=");
	if (s)
		s += 4;
	else
		s = str;
	printf("issuer: %s\n", s);
	OPENSSL_free(str);
	printf("verified: %s\n", (flag_verified)?"Y":"N");

	if (SSL_get_server_tmp_key(ssl, &pktmp))
	{
		switch (EVP_PKEY_id(pktmp)) {
			case EVP_PKEY_RSA:	snprintf(buf, sizeof(buf), "%s", "RSA");
						break;
			case EVP_PKEY_DH:	snprintf(buf, sizeof(buf), "%s", "DH");
						break;
#ifndef OPENSSL_NO_EC
			case EVP_PKEY_EC:	
						EVP_PKEY_get_utf8_string_param(pktmp, OSSL_PKEY_PARAM_GROUP_NAME, (char *)curve, sizeof(curve), NULL);
						snprintf(buf, sizeof(buf), "%s (%s)", "ECDH", curve);
						break;
#endif
			default:		snprintf(buf, sizeof(buf), "%s", OBJ_nid2sn(EVP_PKEY_id(pktmp)));
						break;
		}
		printf("temporary_key: %s (%d bits)\n", buf, EVP_PKEY_bits(pktmp));
		EVP_PKEY_free(pktmp);
	}
	pktmp = X509_get_pubkey(server_cert);

	comp = SSL_get_current_compression(ssl);
	expansion = SSL_get_current_expansion(ssl);

#if defined(HAVE_X509_GET0_EXTENSIONS)
	const X509_ALGOR *sigalg;
	X509_get0_signature(NULL, &sigalg, server_cert);
	OBJ_obj2txt(alg, sizeof(alg), sigalg->algorithm, 0);
#else
	OBJ_obj2txt(alg, sizeof(alg), server_cert->sig_alg->algorithm, 0);
#endif

	printf("pubkeysize: %i\n", EVP_PKEY_bits(pktmp));
	/* x509 standard says this is 1 less than the actual version */
	printf("cert_version: %li\n", (X509_get_version(server_cert)+1));
	printf("notBefore: %s\n", X509_get_notBefore(server_cert)->data);
	ASN1_TIME_diff(&pday, &psec, NULL, X509_get_notAfter(server_cert));
	if (pday < 0)
		snprintf(buf, sizeof(buf), "%s", "EXPIRED");
	else
		snprintf(buf, sizeof(buf), "%d day%s until expiry", pday, (pday>1)?"s":"");
	printf("notAfter: %s (%s)\n", X509_get_notAfter(server_cert)->data, buf);
	printf("algorithm: %s\n", alg);
	/* decode serial */
	bs = X509_get_serialNumber(server_cert);
	buf[0] = '\0';
	for (i=0; i<bs->length; i++)
		snprintf(buf, sizeof(buf), "%s%02x%s", buf, bs->data[i], (i+1<bs->length)?":":"");
	printf("serialnum: %s\n", buf);
	printf("secure_renegotiation: %s\n", (SSL_get_secure_renegotiation_support(ssl))?"YES":"NO");
	if (comp)
	{
		printf("compression: %s\n", SSL_COMP_get_name(comp));
		printf("expansion: %s\n", SSL_COMP_get_name(expansion));
	} else {
		printf("compression: NONE\n");
		printf("expansion: NONE\n");
	}

	if (create_pkp(server_cert, pkpin))
		printf("pubkey_pin: %s\n", pkpin);

	EVP_PKEY_free(pktmp);
	X509_free(server_cert);

	/* if port is 443, send HTTP request */
	if (port == 443)
	{
		snprintf(buf, sizeof(buf), "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni_hostname);
		err = SSL_write(ssl, buf, strlen(buf));
		if (err == strlen(buf))
		{
			/* read response */
			err = SSL_read(ssl, buf, sizeof(buf));
			s = strstr(buf, "Strict-Transport-Security:");
			if (s)
				printf("HSTS: present\n");
			s = strstr(buf, "Public-Key-Pins:");
			if (s)
			{
				printf("HPKP: present\n");
				while ((t = strstr(s, "pin-sha256")))
				{
					tmp[0] = '\0';
					str = strchr(t, '=') + 1;
					if (str && (*str == '"')) str++;
					s = strchr(str, '"');
					if (s)
						*s++ = '\0';
					str2 = match_pkp(str, ssl);
					if (str2)
						snprintf(tmp, sizeof(tmp), " (pinned: %s)", str2);
					else {
						str2 = lookup_pin(str);
						if (str2)
							snprintf(tmp, sizeof(tmp), " (not-pinned: %s)", str2);
						else
							snprintf(tmp, sizeof(tmp), " (not-pinned)");
					}
					printf("HPKP-pin: %s%s\n", str, tmp);
				}
			}
		}
	}
  
	SSL_shutdown(ssl);

	close(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	exit(0);
}

