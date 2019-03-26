#include <iostream>
#include <vector>
#include <string>

using namespace std;

int main()
{
    cout << "Hello" << endl;
    vector<string> v;

    v.push_back("red");
    v.push_back("green");
    v.push_back("blue");

    for (size_t i = 0; i < v.size(); i++)
    {
        cout << v[i] << endl;
    }

    return 0;
}
