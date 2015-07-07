#include <stdio.h>
#ifdef WIN32
#include <wchar.h>
#else
#include <sys/stat.h>
#endif

int main(int argc,char *argv[]) {
	int i;
	char *conf_file;
	for (i=1;i<argc;i++) {
		char *arg=argv[i];
		if (strcmp(arg,"-c")==0 || strcmp(arg,"--config-file")==0) {
			if (++i<argc) {
				conf_file=argv[i];
			} else {
				printf("Error: file name expected after %s option.\n",arg);
				return 0;
			}
		}	
		else {
			printf("Unknow option.");
			return 0;
		}
	}
	char *nm=conf_file;
	FILE *in;
	if (!(in=fopen(nm,"r"))) {
		printf("Can't open config file: %s.", nm);
		return 0;
	}
	int fd=fileno(in);
	struct stat sb;

	/* Note by Paul Rombouts: I am using fstat() instead of stat() here to
	   prevent a possible exploitable race condition */
	if (fd==-1 || fstat(fd,&sb)!=0) {
		printf("Error: Could not stat file.");
	}
	else {
		printf("st_uid is %d", sb.st_uid);
	}
	return 0;
}
