# NAND-Based-Feistel-DES-Cryptographic-Model
Designed and implemented a modified DES encryption model by replacing traditional XOR operations with NAND logic gates.Developed and tested a custom Feistel-based workflow, demonstrating innovation in cryptographic design and evaluating its behavior against key cryptographic principles such as determinism, avalanche effect, and reversibility.

This project presents an innovative implementation of the Data Encryption Standard (DES) where the traditional XOR operation is replaced with NAND-based logic.By reconstructing DES operations using only NAND gates, the project demonstrates how fundamental gate-level transformations can be applied to classical cryptographic algorithms.

#Features

1:NAND-based design – replaces XOR with NAND gates for encryption and decryption.
2:Feistel network structure – preserves the workflow of traditional DES.
3:Bit-level operations – ensures accurate substitution, permutation, and round functions.
4:Encryption & decryption – supports secure transformation cycles.
5:Test cases included – avalanche effect, determinism, and input validation.

#Workflow

1:Input plaintext and key (binary form).
2:Normalize key to 64-bit and generate subkeys.
3:Apply Feistel rounds with NAND-based F-functions.
4:Produce ciphertext after final permutation.
5:Decryption follows the reverse Feistel process.

#Results

1:Verified correct encryption-decryption cycles.
2:Demonstrated avalanche effect (small input/key changes → major output difference).
3:Encryption output differs from standard DES, highlighting the unique NAND substitution.

#Objective
The goal was to explore gate-level innovation in classical cryptography and show how NAND-only computation can provide an alternate perspective on secure encryption design.

#Future Work
1:Performance benchmarking vs. traditional DES.
2:Optimization for lightweight/IoT devices.
3:Extending NAND-based design to other cryptographic primitives.


#Usage
# Clone the repository
git clone https://github.com/yourusername/nand-des.git

# Run the main file
python nand_crypto.py

# Run tests
pytest -v
