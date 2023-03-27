#include <pbc.h>
#include <pbc_test.h>
#include <iostream>
#include <string>
#include <vector>

using std::string;
using std::vector;

int main(int argc, char** argv)
{
	pairing_t pairing;
	pbc_demo_pairing_init(pairing, argc, argv);
	if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");
	
	int n;  //定义用户数量
	std::cout << "请输入用户数量" << std::endl;
	std::cin >> n;
	const int attri = 3;  //定义属性数量

	
	//系统初始化
	element_t g, a, b, c, r1,r2;  //私钥
	
	element_init_G1(g, pairing);

	element_init_Zr(a, pairing);
	element_init_Zr(b, pairing);
	element_init_Zr(c, pairing);
	element_init_Zr(r1, pairing);
	element_init_Zr(r2, pairing);

	element_t v,ga,gb,gc;  //公钥
	element_t *a1=new element_t [2*n];

	element_init_G1(v, pairing);
	element_init_G1(ga, pairing);
	element_init_G1(gb, pairing);
	element_init_G1(gc, pairing);
	for (int i = 0; i < 2*n; ++i) {
		element_init_G1(a1[i], pairing);
	}

	element_random(g);
	element_random(a);
	element_random(b);
	element_random(c);
	element_random(r1);
	element_random(r2);
	
	element_pow_zn(v, g, r1);
	element_pow_zn(ga, g, a);
	element_pow_zn(gb, g, b);
	element_pow_zn(gc, g, c);
	element_t a11;
	element_init_Zr(a11, pairing);
	element_t i1;
	element_init_Zr(i1, pairing);
	for (int i = 0; i < 2*n; ++i) {
		element_set_si(i1, i + 1);
		element_pow_zn(a11, r2, i1);
		element_pow_zn(a1[i], g, a11);
	}

	element_clear(a11);
	element_clear(i1);
	element_clear(r2);

	//产生cs公钥，私钥
	element_t PKcs, SKcs;
	element_init_G1(PKcs, pairing);
	element_init_Zr(SKcs, pairing);

	element_random(SKcs);
	element_pow_zn(PKcs, g, SKcs);

	element_printf("PKcs = %B\n", PKcs);
	element_printf("SKcs = %B\n", SKcs);

	//产生拥有者密钥
	element_t y1, y2;
	element_init_Zr(y1, pairing);
	element_init_Zr(y2, pairing);

	element_t *ek1=new element_t[n];
	element_t *ek2=new element_t[n];
	element_t **ht1=new element_t* [n];
	element_t **ht2=new element_t *[n];

	for (int i = 0; i < n; ++i) {
		ht1[i] = new element_t[n];
		ht2[i] = new element_t[2 * n];
		element_init_G1(ek1[i], pairing);
		element_init_G1(ek2[i], pairing);
		element_random(y1);
		element_random(y2);
		element_pow_zn(ek1[i], PKcs, y1);
		element_pow_zn(ek2[i], v, y1);

		printf("ek%d,1 =", i + 1);
		element_printf("%B\n", ek1[i]);
		printf("ek%d,2 =", i + 1);
		element_printf("%B\n", ek2[i]);

		for (int j = 0; j < n; ++j) {
			element_init_G1(ht1[i][j], pairing);
			element_pow_zn(ht1[i][j], a1[j], y1);  
		}
		for (int j = 0; j < 2*n; ++j) {
			element_init_G1(ht2[i][j], pairing);
			element_pow_zn(ht2[i][j], a1[j], y2);
		}
	}

	element_clear(y1);
	element_clear(y2);

	
	//产生访问者密钥
	//先假设只有一个访问者，拥有所有属性att(属性值用字符串表示，便于哈希,此处默认输入长度为5)
	vector<string> att(attri);
	for (int i = 0; i < attri; ++i) {
		std::cout << "输入属性值" << std::endl;
		std::cin >> att[i];
	}

	element_t SKuap, A, VN, r3,r4;
	element_init_G1(SKuap, pairing);
	element_init_G1(A, pairing);
	element_init_G1(r4, pairing);
	element_init_Zr(VN, pairing);
	element_init_Zr(r3, pairing);

	element_random(VN);
	element_mul(r3, VN, r1);
	element_pow_zn(SKuap, a1[n - 1], r3); //进行初始化

	//假设其能访问所有拥有者，即访问权限s=1~n;
	for (int i = 2; i <= n; ++i) {
		element_pow_zn(r4, a1[n - i], r3);
		element_mul(SKuap, SKuap, r4);
	}
	
	element_printf("SKuap = %B\n", SKuap);

	element_t r, r5;
	element_init_Zr(r, pairing);
	element_init_G1(r5, pairing);

	element_random(r);
	element_mul(r3, a, c);
	element_sub(r3, r3, r);
	element_div(r3, r3, b);
	element_pow_zn(A, g, r3);


	element_printf("A = %B\n", A);

	//假设其具有所有att值
	element_t* Aj = new element_t[attri];
	element_t* Bj = new element_t[attri];

	for (int i = 0; i < attri; ++i) {
		element_random(r3);
		element_from_hash(r4, (void*)&att[i], 5);
		element_pow_zn(r4, r4, r3);
		element_pow_zn(r5, g, r);
		element_init_G1(Aj[i], pairing);
		element_init_G1(Bj[i], pairing);
		element_mul(Aj[i], r4, r5);
		element_pow_zn(Bj[i], g, r3);

		printf("Aj%d =", i + 1);
		element_printf("%B\n", Aj[i]);
		printf("Bj%d =", i + 1);
		element_printf("%B\n", Bj[i]);
	}

	element_clear(r3);
	element_clear(r4);
	element_clear(r5);
	element_clear(r);


	
	//释放初始化指针
	element_clear(g);
	element_clear(a);
	element_clear(b);
	element_clear(c);
	element_clear(r1);
	element_clear(v);
	element_clear(ga);
	element_clear(gb);
	for (int i = 0; i < 2 * n; ++i) {
		element_clear(a1[i]);
	}
	delete[] a1;

	//释放cs
	element_clear(PKcs);
	element_clear(SKcs);

	//释放owner
	for (int i = 0; i < n; ++i) {
		element_clear(ek1[i]);
		element_clear(ek2[i]);
	}
	delete[] ek1;
	delete[] ek2;
	
	for (int i = 0; i < n; ++i) {
		for (int j = 0; j < n; ++j) {
			element_clear(ht1[i][j]);
		}
		for (int j = 0; j < 2 * n; ++j) {
			element_clear(ht2[i][j]);
		}
		delete[] ht1[i];
		delete[] ht2[i];
	}
	delete[] ht1;
	delete[] ht2;
	
	//释放user
	element_clear(SKuap);
	element_clear(A);
	element_clear(VN);

	for (int i = 0; i < attri; ++i) {
		element_clear(Aj[i]);
		element_clear(Bj[i]);
	}
	delete[] Aj;
	delete[] Bj;

	return 0;
}
	