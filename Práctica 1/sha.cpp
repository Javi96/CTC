#include <cstring>
#include <fstream>
#include "sha.h"

using namespace std;

const unsigned int SHA256::sha256_k[64] =
{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
	// Bloques de memoria expandidos para el calculo del hash
	unsigned int w[64];

	// Memoria auxiliar para hacer copias temporales de los valores del hash
	unsigned int temp_hash[8];

	// Variables auxiliares para el calculo de los nuevos valores del hash
	unsigned int t1, t2;

	// Puntero a los sub-bloques
	const unsigned char *sub_block;

	for (int i = 0; i < (int)block_nb; i++)
	{
		// Desplazamos el mensaje 6 bits
		sub_block = message + (i << 6);
		//Empaqueta en w[] 256 bits. 32 bits empaquetados en uno


		// Aplicamos una funcion de compresion a los bloques
		for (int j = 0; j < 16; j++)
		{
			SHA2_PACK32(&sub_block[j << 2], &w[j]);
		}

		// Calcula los bloques de memoria expandidos W[j]
		for (int j = 16; j < 64; j++)
		{
			/*
			Cada bloque de memoria exp es definido por los bloques
			en j=0, j=7 con incrementos de 1 por vuelta.
			Aplicamos funciones phro sobre j=14, j=1 con incremento de 1
			por vuelta
			*/
			w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
		}

		// Copiamos los valores del hash en memoria auxiliar
		for (int j = 0; j < 8; j++)
		{
			temp_hash[j] = hash[j];
		}

		// Calculamos los valores del hash
		for (int j = 0; j < 64; j++)
		{
			t1 = temp_hash[7] + SHA256_F2(temp_hash[4]) + SHA2_CH(temp_hash[4], temp_hash[5], temp_hash[6])
				+ sha256_k[j] + w[j];
			t2 = SHA256_F1(temp_hash[0]) + SHA2_MAJ(temp_hash[0], temp_hash[1], temp_hash[2]);
			temp_hash[7] = temp_hash[6];
			temp_hash[6] = temp_hash[5];
			temp_hash[5] = temp_hash[4];
			temp_hash[4] = temp_hash[3] + t1;
			temp_hash[3] = temp_hash[2];
			temp_hash[2] = temp_hash[1];
			temp_hash[1] = temp_hash[0];
			temp_hash[0] = t1 + t2;
		}

		// Copiamos los valores resultado del hash
		for (int j = 0; j < 8; j++)
		{
			hash[j] += temp_hash[j];
		}
	}
}

void SHA256::init()
{
	hash[0] = 0x6a09e667;
	hash[1] = 0xbb67ae85;
	hash[2] = 0x3c6ef372;
	hash[3] = 0xa54ff53a;
	hash[4] = 0x510e527f;
	hash[5] = 0x9b05688c;
	hash[6] = 0x1f83d9ab;
	hash[7] = 0x5be0cd19;

	mem_len = 0;
	mem_tot_len = 0;
}

void SHA256::update(const unsigned char *message, unsigned int len)
{
	//Número de bloques
	unsigned int block_nb;
	//Nueva longitud, longitud restante, longitud temporal
	unsigned int new_len, rem_len, tmp_len;
	//Puntero a un punto concreto del mensaje
	const unsigned char *shifted_message;
	//64 - m_len
	tmp_len = BLOCK_SIZE - mem_len;

	//Si la longitud del mensaje es menor que el resultado anterior
	//nos quedamos con len, si es más pequeño que el máximo que podemos coger (tmp_len), si no, cogemos el máximo
	if (len < tmp_len)
		rem_len = len;
	else
		rem_len = tmp_len;

	//Copiamos rem_lem bits del mensaje en el bloque de 128 bits m_block
	memcpy(&mem_block[mem_len], message, rem_len);

	//Si la longitud del mensaje + m_len es menor que 64
	if (mem_len + len < BLOCK_SIZE) {
		//sumamos len a m_len, nos cabe en el bloque y salimos
		mem_len += len;
		return;
	}

	//new_len es el tamaño de lo que no se ha podido leer
	new_len = len - rem_len;
	//Calculamos el numero de bloques que vamos a necesitar para guardar new_len en m_block
	block_nb = new_len / BLOCK_SIZE;
	//Avanzamos hasta el punto donde me he quedado leyendo
	shifted_message = message + rem_len;
	//Transformamos el bloque que tenemos guardado
	transform(mem_block, 1);
	//Transformamos los block_nb que no hemos podido guardar
	transform(shifted_message, block_nb);
	//Calculamos el espacio disponible en el bloque actual 
	rem_len = new_len % BLOCK_SIZE;
	//Copias rem_len a partir de shifted message en el primer lugar sin guardar
	memcpy(mem_block, &shifted_message[block_nb << 6], rem_len);

	mem_len = rem_len;
	mem_tot_len += (block_nb + 1) << 6;
}

void SHA256::final(unsigned char *digest)
{
	unsigned int block_nb;
	unsigned int pm_len;
	unsigned int len_b;
	int i;

	//2 o 1
	block_nb = (1 + ((BLOCK_SIZE - 9)
		< (mem_len % BLOCK_SIZE)));

	len_b = (mem_tot_len + mem_len) << 3;
	pm_len = block_nb << 6;
	memset(mem_block + mem_len, 0, pm_len - mem_len);
	mem_block[mem_len] = 0x80;
	SHA2_UNPACK32(len_b, mem_block + pm_len - 4);
	transform(mem_block, block_nb);

	for (i = 0; i < 8; i++) {
		SHA2_UNPACK32(hash[i], &digest[i << 2]);
	}
}

string sha256(string input)
{

	unsigned char digest[SHA256::NUMBER_FORMAT_SIZE];
	
	//Creamos un bloque de memoria digest y lo rellenamos DIGEST_SIZE bytes con 0's
	memset(digest, 0, SHA256::NUMBER_FORMAT_SIZE); //<- Aquí tenemos un bloque de 32 bits con todo a 0

	//Creamos el objeto
	SHA256 ctx = SHA256();
	
	//Lo inicializamos
	ctx.init();
	
	//Pasamos un array con el equivalente c-string del input y la longitud del mismo
	ctx.update((unsigned char*)input.c_str(), input.length());
	ctx.final(digest);

	char buf[2 * SHA256::NUMBER_FORMAT_SIZE + 1];
	buf[2 * SHA256::NUMBER_FORMAT_SIZE] = 0;

	for (unsigned int i = 0; i < SHA256::NUMBER_FORMAT_SIZE; i++)
		sprintf(buf + i * 2, "%02x", digest[i]);

	return string(buf);
}