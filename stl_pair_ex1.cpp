#include <bits/stdc++.h>
using namespace std;


int main(){
	int a[3] = {3, 1, 2};
	char b[3] = {'G','E', 'K'};
	pair <int, char> p[3]; 
	
	for (int i=0; i<3; i++){
		p[i]={a[i],b[i]};
	}
		
	sort(p, p+4);
	for (int i=0; i<3; i++) 
		cout << p[i].second<<" "; 
	
	return 0;
}
