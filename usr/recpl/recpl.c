//usr/bin/env/gcc gcc
#include<string>
void fcopy(FILE from, FILE to) {
	string a;
	fopen(from, "r");
	fopen(to, "w");
	fscanf(from, "%s", a);
	fprintf(to, "%s", a);
	fclose(from);
	fclose(to);
}

FILE* joindll(FILE* Winexec, FILE* *dll[]) {
	string a;
	Winexec = fopen(Winexec, "w");
	for(int i=0; dll[i]; i++) {
		dll[i] = fopen(dll[i], "r");
		a += dll[i].read();
		fclose(dll[i]);
	}
	Winexec.write(a);
	fcopy(Winexec.name, Winexec.name.replase(Winexec.name.find(".exe"), ".djwe", 4));
	fclose(Winexec);
	return Winexec;
}
int main(char argc[], string argv[]) {
	switch(argc[]) {
		case "-c":
			joindll((argv.replase(while((a = argv.find(" ")) != -1) tmp[i]=a, i++));
			FILE* f=fopen(joindll.Winexec.replase(Winexec.name.find(".exe"), ".djwe", 4));
			fcopy(f, "~/usr/bin/Cache_default/"+f.replace(f.find(".djwe"), ".tmp", 3));
			system("./Scripts/compile "+f.replace(f.find(".djwe"), ".tmp", 3));
			printf("compiled.");
			exit(0);
		case "-e":
			joindll((argv.replase(while((a = argv.find(" ")) != -1) tmp[i]=a, i++));
			FILE* f=fopen(joindll.Winexec.replase(Winexec.name.find(".exe"), ".djwe", 4));
			fcopy(f, "~/usr/bin/Cache_default/"+f.replace(f.find(".djwe"), ".tmp", 3));
			system("./Scripts/compile "+"~/usr/bin/Cache_default/"+f.replace(f.find(".djwe"), ".tmp", 3));
			system("~/usr/bin/Cache_default/"+f.replace(f.find(".djwe"), ".tmp", 3));
			printf("executing.");
			if(!system("ps aux | grep "+"~/usr/bin/Cache_default/"+f.replace(f.find(".djwe"), ".tmp", 3)+" | grep -v grep")) exit(0);
	}
}