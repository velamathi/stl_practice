#include <bits/stdc++.h>
using namespace std;


int main(){
	pair <int, int> p1(10,20);
	pair <int, int> p11;
	p11 = {121, 213};
	//~ p11 = make_pair(121, 213);
	pair <int, char> p2(10,'z');
	pair <int, string> p3(10, "FunkyGunkyMonkey");
	cout <<p1.first <<" " << p1.second<<"\n";
	cout <<p11.first <<" " << p11.second<<"\n";
	cout <<p2.first <<" " << p2.second<<"\n";
	cout <<p3.first <<" " << p3.second<<"\n";
	
	
	pair <int, int> p(1,12) , pz(9,12);
	cout << (p==pz) << " ";
	cout << (p!=pz) << " ";
	cout << (p>pz) << " ";
	cout << (p<pz) << " ";
	
	
	
	return 0;
}
