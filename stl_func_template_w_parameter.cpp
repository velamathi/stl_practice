#include <bits/stdc++.h>
using namespace std;

template <class T, int limit>
T arrMax(T arr[], int n){
	if (n> limit){
		cout <<"More than the limit set"<<"\n";
		return 0;
	}
	T res = arr[0];
	for (int i=1; i<n; i++)
		if (arr[i]>res)
			res = arr[i];
	return res;
}


int main(){
	int arr1[] = { 10, 40, 3,343,12,12,232,112,323};
	const int x = 8;
	cout << arrMax<int,x> (arr1, 9)<<"\n";
	float arr2[] = { 10.5, 3.5, 1.5, 30.5}; 
	cout << arrMax<float,5> (arr2, 4)<<"\n";
	
	
	return 0;
}
