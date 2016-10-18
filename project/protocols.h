#pragma once
class protocols
{

	int index;
	char* name;
	

public:
	static protocols protocol[20];
	protocols();
	protocols(int, char*);
	~protocols();
	static char* getname(int );
};

