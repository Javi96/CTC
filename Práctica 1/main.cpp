#include <iostream>
#include "sha.cpp"
#include <string>

using namespace std;

int main(int argc, char *argv[])
{
	//Pedimos el mensaje
	cout << "Introduzca el mensaje: ";
	//Definimos un input
	string input;
	//Recogemos el input
	cin >> input;
	//LLamamos a la función y mostramos el resultado
	string output1 = sha256(input);
	cout << "sha256('" << input << "'):" << output1 << endl;

	return 0;
}