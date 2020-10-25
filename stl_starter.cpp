#include <bits/stdc++.h>
#include <algorithm>

using namespace std;

int main(){
	int arr[] = {10, 1 5,8,20 };
	sort(arr, arr+4);
	for (int i=0; i<4; i++) cout << arr[i] << " " ; 
	
	cout <<"\n";
	
	if ((binary_search(arr, arr+4, 8)))
		cout << "Present";
	else
		cout << "Not present";
	
	return 0;
}
