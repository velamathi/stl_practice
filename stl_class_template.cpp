#include <bits/stdc++.h>
using namespace std;

template <class T>
struct Pair{
	T x,y;
	Pair(T i, T j) { x =i; y=j; }
	T getFirst() { return x; } 
	T getSecond() { return y; } 
};

int main(){
	Pair<int> p1(10, 20);
	cout << p1.getFirst() <<" " ;
	cout << p1.getSecond() <<" " ;
	
	
	
	return 0;
}
