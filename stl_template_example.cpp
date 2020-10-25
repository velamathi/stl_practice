#include <bits/stdc++.h>
using namespace std;

template <typename T>
T mymax(T x, T y){
	return (x>y)? x:y;
}


int main(){
	cout << mymax<int> (3,7) << "\n";
	cout << mymax<char> ('c','z') << "\n";
	
	return 0;
}
