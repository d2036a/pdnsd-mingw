/* netdev.c - Test network devices for existence and status

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2002, 2003, 2011 Paul A. Rombouts

  This file is part of the pdnsd package.

  pdnsd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  pdnsd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with pdnsd; see the file COPYING. If not, see
  <http://www.gnu.org/licenses/>.
*/

/*
 * Portions are under the following copyright and taken from FreeBSD
 * (clause 3 deleted as it no longer applies):
 *
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/if.h,v 1.58.2.1 2000/05/05 13:37:04 jlemon Exp $
 */

#include <config.h>
#include "ipvers.h"
#include <sys/stat.h>
#ifdef WIN32
#include <ntddndis.h>
#include <wbemidl.h>
#else
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#endif
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include "helpers.h"
#include "netdev.h"
#include "error.h"

#ifdef WIN32
const GUID CLSID_WbemLocator = { 0x4590F811,0x1D3A,0x11D0,{ 0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24 } };
#endif

#if (TARGET==TARGET_BSD)
/* Taken from FreeBSD net/if.h rev. 1.58.2.1 */
#define	SIZEOF_ADDR_IFREQ(ifr) \
	((ifr).ifr_addr.sa_len > sizeof(struct sockaddr) ? \
	 (sizeof(struct ifreq) - sizeof(struct sockaddr) + \
	  (ifr).ifr_addr.sa_len) : sizeof(struct ifreq))
#elif (TARGET==TARGET_CYGWIN) || (TARGET==TARGET_MINGW)
#define SIZEOF_ADDR_IFREQ(ifr) (sizeof(struct sockaddr))
#endif

#define MAX_SOCKETOPEN_ERRS 10
static volatile unsigned long socketopen_errs=0;

/*
 * Portions of the following code are Linux/FreeBSD specific.
 * Please write interface-detection routines for other flavours of Unix if you can and want.
 */

#if (TARGET==TARGET_LINUX) || (TARGET==TARGET_BSD) || (TARGET==TARGET_CYGWIN) || (TARGET==TARGET_MINGW)
# if (TARGET==TARGET_LINUX)

static volatile unsigned long isdn_errs=0;

#  ifdef ISDN_SUPPORT

/*
 * Test the status of an ippp interface. Taken from the isdn4k-utils (thanks!) and adapted
 * by me (I love free software!)
 * This will not work with older kernels.
 * If your kernel is too old or too new, just try to get the status as uptest=exec command
 * This will work, although slower.
 */

#   include <linux/isdn.h>

int statusif(char *name)
{
	isdn_net_ioctl_phone phone;
	int isdninfo,rc=0;

	if ((isdninfo = open("/dev/isdninfo", O_RDONLY))<0) {
		if (++isdn_errs<=2) {
			log_warn("Could not open /dev/isdninfo for uptest: %s",strerror(errno));
		}
		return 0;
	}

	strncp(phone.name, name, sizeof(phone.name));
	if (ioctl(isdninfo, IIOCNETGPN, &phone)==0)
		rc=1;
	close(isdninfo);
	return rc;
}
#  endif

/*
 * Test whether the network interface specified in ifname and its
 * associated device specified in devname have locks owned by the
 * same process.
 */
int dev_up(char *ifname, char *devname)
{
 	FILE *fd;
 	int pidi, pidd, rv;

	{
	  char path[sizeof("/var/run/.pid")+strlen(ifname)];
	  stpcpy(stpcpy(stpcpy(path,"/var/run/"),ifname),".pid");
	  if ((fd=fopen(path, "r")) == NULL )
	    return 0;

	  if (fscanf(fd, "%d", &pidi) != 1 ) {
	    fclose(fd) ;
	    return 0;
	  }
	  fclose(fd);
	}

	{
	  char path[sizeof("/var/lock/LCK..")+strlen(devname)];
	  stpcpy(stpcpy(path,"/var/lock/LCK.."),devname);
	  if ((fd=fopen(path, "r")) == NULL)
	    return 0;

	  if (fscanf(fd, "%d", &pidd) != 1) {
	    fclose(fd);
	    return 0;
	  }
	  fclose(fd);
	}

 	if (pidi != pidd)
		return 0;
	/* Test whether pppd is still alive */
	rv=kill(pidi,0);
	return (rv==0 || (rv==-1 && errno!=ESRCH));
}


# endif /*(TARGET==TARGET_LINUX)*/

/*
 * Test whether the network device specified in devname is up and
 * running (returns -1) or non-existent, down or not-running (returns 0)
 *
 * For windows, get interface status from WMI using COM.
 *
 * Note on IPv6-Comptability: rfc2133 requires all IPv6 implementation
 * to be backwards-compatible to IPv4 in means of permitting socket(PF_INET,...)
 * and similar. So, I don't put code here for both IPv4 and IPv6, since
 * I use that socket only for ioctls. If somebody notices incompatabilities,
 * please notify me.
 */
# ifdef WIN32
int if_up(char *devname)
{
	/* Get network adapter status from WMI using COM */
        DWORD ifStatus = 0;
	HRESULT hres;
        IWbemLocator *locator=NULL;
        IWbemServices *services=NULL;
        IEnumWbemClassObject *results=NULL;
        BSTR resource=SysAllocString(L"ROOT\\CIMV2");
        BSTR language=SysAllocString(L"WQL");
        LPWSTR query_h=L"SELECT NetConnectionStatus FROM Win32_NetworkAdapter " 
                       L"WHERE NetConnectionID = ";

	size_t len=_mbslen(devname);
        size_t cont=0;

        /* Count how many single single quotes(') in devname for escap */
        /* single quotes(') in WQL query string */
        char *pc=devname;
        for(; pc=(char *)_mbschr(pc,'\''); pc++) {
                cont++;
        }
        /* Need to add two single quotes(') at begin and after devname */
        WCHAR query_str[len+cont+wcslen(query_h)+3];
        wcscpy(query_str,query_h);
        /* Add start single quote(') to query string before append devname */
        wcscat(query_str,L"'");
        WCHAR connid[len+1];
        mbstowcs(connid,devname,len+1);
        WCHAR *pw, *qw=connid;
        for(pw=connid; pw=wcschr(pw, L'\''); pw++) {
                /* Escape single quotes(') in devname */
                wcsncat(query_str,qw,pw-qw);
                wcscat(query_str,L"\\");
                qw=pw;
        }
        wcscat(query_str,qw);
        /* Append terminal single quote(') to query string */
        wcscat(query_str,L"'");
        BSTR query=SysAllocString(query_str);	

        // initialize COM
        hres=CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
        	log_warn("Failed to initialize COM library:0x%x\n", hres);
        	goto cleanup;
    	}
        hres=CoInitializeSecurity(NULL, -1, NULL, NULL,
                             RPC_C_AUTHN_LEVEL_DEFAULT,
                             RPC_C_IMP_LEVEL_IMPERSONATE,
                             NULL, EOAC_NONE, NULL);
	if (FAILED(hres))
    	{
        	log_warn("Failed to initialize security:0x%x\n",hres);
        	CoUninitialize();
        	goto cleanup;
    	}
        // connect to WMI
        hres=CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                         &IID_IWbemLocator, (LPVOID *) &locator);
	if (FAILED(hres))
    	{
        	log_warn("Failed to create IWbemLocator object:0x%x\n",hres);
        	CoUninitialize();
        	goto cleanup;
    	}
        hres=locator->lpVtbl->ConnectServer(locator,
				resource,
				NULL, NULL, NULL, 0,
				NULL, NULL, &services);
	if (FAILED(hres))
	{
        	log_warn("Could not connect:0x%x\n",hres);
        	locator->lpVtbl->Release(locator);     
        	CoUninitialize();
        	goto cleanup;
    	}
        // issue a WMI query
        hres=services->lpVtbl->ExecQuery(services, language, query,
                                    WBEM_FLAG_BIDIRECTIONAL,
                                    NULL, &results);
	if (FAILED(hres))
    	{
        	log_warn("Query for processes failed:0x%x\n",hres);
        	services->lpVtbl->Release(services);
        	locator->lpVtbl->Release(locator);     
        	CoUninitialize();
        	goto cleanup;
    	}
        // list the query results
        else
	{
                IWbemClassObject *result = NULL;
                ULONG returnedCount = 0;
                // enumerate the retrieved objects
                while((results->lpVtbl->Next(results, WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) {
                        VARIANT status;
                        // obtain the desired properties of the next result 
                        result->lpVtbl->Get(result, L"NetConnectionStatus", 0, &status, 0, 0);
                        // release the current result object
                        result->lpVtbl->Release(result);
                        if(status.intVal==2) {
                                ifStatus=-1;
                                break;
                        }
                }
        }
        // release WMI COM interfaces
        results->lpVtbl->Release(results);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);
        // unwind everything else we've allocated
        CoUninitialize();

cleanup:
        SysFreeString(query);
        SysFreeString(language);
        SysFreeString(resource);

	return ifStatus;
}
# else
int if_up(char *devname)
{
	int sock;
	struct ifreq ifr;
#  if (TARGET==TARGET_LINUX)
	unsigned int devnamelen=strlen(devname);
	if (devnamelen>4 && devnamelen<=6 && strncmp(devname,"ippp",4)==0) {
		/* This function didn't manage the interface uptest correctly. Thanks to
		 * Joachim Dorner for pointing out.
		 * The new code (statusif()) was shamelessly stolen from isdnctrl.c of the
		 * isdn4k-utils. */
#   ifdef ISDN_SUPPORT
		return statusif(devname);
#   else
		if (isdn_errs++==0) {
			log_warn("An ippp? device was specified for uptest, but pdnsd was compiled without ISDN support.");
			log_warn("The uptest result will be wrong.");
		}
#   endif
		/* If it doesn't match our rules for isdn devices, treat as normal if */
	}
#  endif
	if ((sock=socket(PF_INET,SOCK_DGRAM, IPPROTO_UDP))==-1) {
		if(++socketopen_errs<=MAX_SOCKETOPEN_ERRS) {
			log_warn("Could not open socket in if_up(): %s",strerror(errno));
		}
		return 0;
	}
	strncp(ifr.ifr_name,devname,IFNAMSIZ);
	if (ioctl(sock,SIOCGIFFLAGS,&ifr)==-1) {
		close(sock);
		return 0;
	}
	close(sock);
	return (ifr.ifr_flags&IFF_UP) && (ifr.ifr_flags&IFF_RUNNING);
}
# endif

# if (TARGET==TARGET_LINUX)
#  ifdef ENABLE_IPV6
#define MAX_IF_INET6_OPEN_ERRS 10
static volatile unsigned long if_inet6_open_errs=0;
#  endif

int is_local_addr(pdnsd_a *a)
{
	int res=0;

#  ifdef ENABLE_IPV4
	if (run_ipv4) {
		int i,sock;
		struct ifreq ifr;
		if ((sock=socket(PF_INET,SOCK_DGRAM, IPPROTO_UDP))==-1) {
			if(++socketopen_errs<=MAX_SOCKETOPEN_ERRS) {
				log_warn("Could not open socket in is_local_addr(): %s",strerror(errno));
			}
			return 0;
		}
		for (i=1;i<255;i++) {
			ifr.ifr_ifindex=i;
			if (ioctl(sock,SIOCGIFNAME,&ifr)==-1) {
				/* There may be gaps in the interface enumeration, so just continue */
				continue;
			}
			if (ioctl(sock,SIOCGIFADDR, &ifr)==-1) {
				continue;
			}
			if (((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr.s_addr==a->ipv4.s_addr) {
				res=1;
				break;
			}
		}
		close(sock);
	}

#  endif
#  ifdef ENABLE_IPV6
	ELSE_IPV6 {
		char   buf[40];
		FILE   *f;
		struct in6_addr b;
		/* the interface configuration and information retrieval is obiously currently done via
		 * rt-netlink sockets. I think it is relatively likely to change in an incompatible way the
		 * Linux kernel (there seem to be some major changes for 2.4).
		 * Right now, I just analyze the /proc/net/if_inet6 entry. This may not be the fastest, but
		 * should work and is easy to adapt should the format change. */
		if (!(f=fopen("/proc/net/if_inet6","r"))) {
			if(++if_inet6_open_errs<=MAX_IF_INET6_OPEN_ERRS) {
				log_warn("Could not open /proc/net/if_inet6 in is_local_addr(): %s",strerror(errno));
			}
			return 0;
		}
		/* The address is at the start of the line. We just read 32 characters and insert a ':' 7
		 * times. Such, we can use inet_pton conveniently. More portable, that. */
		for(;;) {
			int i,ch; char *p=buf;
			for (i=0;i<32;i++) {
				if(i && i%4==0) *p++ = ':';
				if ((ch=fgetc(f))==EOF)
					goto fclose_return; /* we are at the end of the file and haven't found anything.*/
				if(ch=='\n') goto nextline;
				*p++ = ch;
			}
			*p=0;
			if (inet_pton(AF_INET6,buf,&b) >0) {
				if (IN6_ARE_ADDR_EQUAL(&b,&a->ipv6)) {
					res=1;
					goto fclose_return;
				}
			}
			do {
				if ((ch=fgetc(f))==EOF) goto fclose_return;
			} while(ch!='\n');
		nextline:;
		}
	fclose_return:
		fclose(f);
	}
#  endif
	return res;
}

# else /*(TARGET==TARGET_BSD) || (TARGET==TARGET_CYGWIN)i || (TARGET==TARGET_MINGW) */

#define MAX_SIOCGIFCONF_ERRS 4
static volatile unsigned long siocgifconf_errs=0;

int is_local_addr(pdnsd_a *a)
{
	int retval=0, sock, cnt;
#  ifdef WIN32
	INTERFACE_INFO ifo[26];
        DWORD ifo_len;
#  else
        struct ifconf ifc;
	char buf[2048];
#  endif

	if ((sock=socket(PF_INET,SOCK_DGRAM, IPPROTO_UDP))==-1) {
		if(++socketopen_errs<=MAX_SOCKETOPEN_ERRS) {
#  ifdef WIN32
			log_warn("Could not open socket in is_local_addr(): %d",WSAGetLastError());
#  else
			log_warn("Could not open socket in is_local_addr(): %s",strerror(errno));
#  endif
		}
		return 0;
	}

#  ifdef WIN32
	if ((WSAIoctl(sock,SIO_GET_INTERFACE_LIST,
                     NULL,0,
                     ifo,sizeof(ifo),
                     &ifo_len, NULL, NULL))!=0) {
                if(++siocgifconf_errs<=MAX_SIOCGIFCONF_ERRS) {
                        log_warn("(WSAIoctl() call with request SIOCGIFCONF failed in is_local_addr(): %s",strerror(errno));
                }
		goto close_sock_return;
        }

        for (cnt = 0; cnt<(int)(ifo_len/sizeof(INTERFACE_INFO)); cnt++) {
                if (SEL_IPVER(ifo[cnt].iiAddress.Address.sa_family==AF_INET &&
                               ifo[cnt].iiAddress.AddressIn.sin_addr.s_addr==a->ipv4.s_addr,
                              ifo[cnt].iiAddress.Address.sa_family==AF_INET6 &&
                               IN6_ARE_ADDR_EQUAL(&ifo[cnt].iiAddress.AddressIn6.sin6_addr,
                                                 &a->ipv6)))
                {
                        retval=1;
                        break;
                }
        }
#  else
	ifc.ifc_len=sizeof(buf);
	ifc.ifc_buf=buf;
	if (ioctl(sock,SIOCGIFCONF,&ifc)==-1) {
		if(++siocgifconf_errs<=MAX_SIOCGIFCONF_ERRS) {
			log_warn("ioctl() call with request SIOCGIFCONF failed in is_local_addr(): %s",strerror(errno));
		}
	        goto close_sock_return;
	}

	cnt=0;
	while(cnt+sizeof(struct ifreq)<=ifc.ifc_len) {
		struct ifreq *ir= (struct ifreq *)(buf+cnt);
		cnt += SIZEOF_ADDR_IFREQ(*ir);
		if (cnt>ifc.ifc_len)
			break;
		if (SEL_IPVER(ir->ifr_addr.sa_family==AF_INET &&
			       ((struct sockaddr_in *)&ir->ifr_addr)->sin_addr.s_addr==a->ipv4.s_addr,
			      ir->ifr_addr.sa_family==AF_INET6 &&
			       IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)&ir->ifr_addr)->sin6_addr,
						  &a->ipv6)))
		{
			retval=1;
			break;
		}
	}
#  endif

 close_sock_return:
#  ifdef WIN32
	closesocket(sock);
#  else
	close(sock);
#  endif

	return retval;
}

# endif

#else
# error "Huh. No OS macro defined."
#endif
