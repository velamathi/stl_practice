#include <bits/stdc++.h>
using namespace std;

template <class T>
T arrMax(T arr[], int n){
	T res = arr[0];
	for (int i=1; i<n; i++)
		if (arr[i]>res)
			res = arr[i];
	return res;
}


int main(){
	int arr1[] = { 10, 40, 3};
	cout << arrMax<int> (arr1, 3)<<"\n";
	float arr2[] = { 10.5, 3.5, 1.5, 30.5}; 
	cout << arrMax<float> (arr2, 4)<<"\n";
	
	
	return 0;
}
