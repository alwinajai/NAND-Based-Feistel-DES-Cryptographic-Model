# NAND-Based-Feistel-DES-Cryptographic-Model
Designed and implemented a modified DES encryption model by replacing traditional XOR operations with NAND logic gates.Developed and tested a custom Feistel-based workflow, demonstrating innovation in cryptographic design and evaluating its behavior against key cryptographic principles such as determinism, avalanche effect, and reversibility.

This project presents an innovative implementation of the Data Encryption Standard (DES) where the traditional XOR operation is replaced with NAND-based logic.By reconstructing DES operations using only NAND gates, the project demonstrates how fundamental gate-level transformations can be applied to classical cryptographic algorithms.

#Features
NAND-based design – replaces XOR with NAND gates for encryption and decryption.

Feistel network structure – preserves the workflow of traditional DES.

Bit-level operations – ensures accurate substitution, permutation, and round functions.

Encryption & decryption – supports secure transformation cycles.

Test cases included – avalanche effect, determinism, and input validation.

#Workflow
Input plaintext and key (binary form).

Normalize key to 64-bit and generate subkeys.

Apply Feistel rounds with NAND-based F-functions.

Produce ciphertext after final permutation.

Decryption follows the reverse Feistel process.

#Results
Verified correct encryption-decryption cycles.

Demonstrated avalanche effect (small input/key changes → major output difference).

Encryption output differs from standard DES, highlighting the unique NAND substitution.

#Objective
The goal was to explore gate-level innovation in classical cryptography and show how NAND-only computation can provide an alternate perspective on secure encryption design.

#Future Work
Performance benchmarking vs. traditional DES.

Optimization for lightweight/IoT devices.

Extending NAND-based design to other cryptographic primitives.


#Usage
# Clone the repository
git clone https://github.com/yourusername/nand-des.git

# Run the main file
python nand_crypto.py

# Run tests
pytest -v
