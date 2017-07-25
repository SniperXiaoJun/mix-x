#include <fstream>
#include <ios>

int main() {
	std::ifstream infile("test.dat", std::ios_base::binary);
	std::ofstream outfile("test~.dat", std::ios_base::binary);

	outfile << infile.rdbuf();
}