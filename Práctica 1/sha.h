#ifndef SHA_H
#define SHA_H
#include <string>

class SHA256
{	
public:

	/*
	Inicializa los valores del hash
	*/
	void init();

	/*
	Actualiza el mensaje en funcion de la longitud indicada*/
	void update(const unsigned char *message, unsigned int len);

	/*
	Compacta el hash
	*/
	void final(unsigned char *digest);

	//Bloques de 64 bits
	static const unsigned int BLOCK_SIZE = (512 / 8);

	// Constante para 32 bits
	static const unsigned int NUMBER_FORMAT_SIZE = (256 / 8);

protected:

	/*
	Funcion de computacion del hash
	*/
	void transform(const unsigned char *message, unsigned int block_nb);
	unsigned int mem_tot_len;
	unsigned int mem_len;

	//array de caracteres de 128 bits (2*64)
	unsigned char mem_block[2 * BLOCK_SIZE];
	unsigned int hash[8];

	const static unsigned int sha256_k[];

};

std::string sha256(std::string input);

//Desplaza desde la posicion n x bits a la derecha
#define SHA2_SHFR(x, n)    (x >> n) 
//Hace una movida muy chunga pero es una rotación a la derecha
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n))) 
//Hace una movida muy chunga pero es una rotación a la izquierda
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n))) 
// XOR(x & y, !x & z)
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z)) 
// True si solo uno de los valores es 1 o los tres son 1
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z)) 
// Funcion sigma sub0
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
// Funcion sigma sub1
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
// Funcion phro sub0
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
// Funcion phro sub1
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))

/*
Funcion de descompresion
*/
#define SHA2_UNPACK32(x, str)                         \
{													  \
    *((str) + 3) = (unsigned char) ((x)      );       \
    *((str) + 2) = (unsigned char) ((x) >>  8);       \
    *((str) + 1) = (unsigned char) ((x) >> 16);       \
    *((str) + 0) = (unsigned char) ((x) >> 24);       \
}

/*
Funcion de compresion
*/
#define SHA2_PACK32(str, x)							\
{													\
    *(x) =   ((unsigned int) *((str) + 3)      )    \
           | ((unsigned int) *((str) + 2) <<  8)    \
           | ((unsigned int) *((str) + 1) << 16)    \
           | ((unsigned int) *((str) + 0) << 24);   \
}
#endif