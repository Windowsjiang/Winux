#pragma once
#ifdef WINUX_BASE
#define __WIN_LINUX__
/* Winux base defination, version 1.0.0(build 1001)
* Copyright (C) Windowsjiang 2024-2025, All reserved
*/
#include<Windows.h>
#include<Wmi/api.c>
#include<ntos.h>
#include<string>
#include<string.h>
#include<time.h>
#include<stdlib.h>

typedef BOOLEAF bool
typedef PHADLE hdl
typedef PETHREAD pe_thr
typedef PVOID pnon
typedef VOID non
struct DllRegisterEntry(FILE dllfile) {
	srand(time(nullptr));
	string Entry="RegServer" + (rand()%65536+0) + "Entry";
	
	int register(FILE dllfile, DllRegisterEntry entry) {
		non;
	}
};

struct THREADS(int &_pid, FILE &image, user &usr) {
	string level;
	string statu="running";
	FILE img2 = img = image;
	int pid = _pid;
	user ruser = user
	rands(time(nullptr));
	if(img.read().find("Windowsjiang") != -1 && img.read().find("Microsoft") != -1 || rusr.name == "SYSTEM") {
		level = "top";
		while(1) protect(THREADS(rand()%65536 +0, image), user("SYSTEM"));
	}
	
	void taskkill(THREADS &thr) {
		this->statu="stop";
		del(thr);
		return;
	}
	
	void protect(THREADS &thr) {
		if(this->level == "top") {
			if(!(callable(thr))) blue_screen("0xc000001");
			else if(fclose(img2)) blue_screen("0xc000000");
			else statu="top";
		}
		else return;
	}
};

typedef in_obj;
typedef out_obj;
typedef BIOS;

void blue_screen(string error) {
	char tmp;
	int i=0;
	while(1) THREADS::taskkill(i++);
	printf("Your system tables has been damaged by error"+error+".\n press any key to restart.");
	if(cin >> tmp) system("sudo ./lib/bootconfig.c");
}

struct ms_installer(FILE __installer, FILE __cab_database) {
	FILE installer = __installer;
	FILE cab_database = __cab_database;
	if(!(cab_database.find(".cab"))) throw "invalid database format.";
	
	void install(FILE &installer, FILE &cab_database) {
		
	}
	
	struct Completex(int a, int b) {
		Completex &opreator+(int a1, int b1, int a2, int b2) {
			return Completex(a1+a2, b1+b2);
		}
	};
};
#endif