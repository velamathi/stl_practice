#include <bits/stdc++.h>
using namespace std;

template <class T>
T mymax(T x, T y){
	return (x>y)? x:y;
}


int main(){
	cout << mymax<int> (3,7) << "\n";
	cout << mymax<char> ('c','z') << "\n";
	cout << mymax<float> (312.13133,1312.13133324424242) << "\n";
	
	return 0;
}
