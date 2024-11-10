# Data Security using Cryptography and Steganography

This project provides a comprehensive tool for securing sensitive information through **cryptography** (to encrypt data) and **steganography** (to hide data within multimedia files). This dual-layered approach ensures both data confidentiality and obscurity, making unauthorized access or detection of the data significantly more challenging.

## Features

- **Data Encryption and Decryption**
  - Encrypts data using popular cryptographic algorithms (RSA, AES, and TripleDES), securing data content with unique encryption keys.
  - Offers flexibility between symmetric (AES, TripleDES) and asymmetric (RSA) encryption based on the required security level and application context.

- **Data Hiding with Steganography**
  - Embeds encrypted data within image files, rendering it undetectable to the human eye. This masks the presence of data, concealing it within a media file (e.g., JPEG or PNG).
  - Enhances secure transmission and storage by using the image file as a 'carrier' for hidden data.

- **Logging of Security Operations**
  - Logs all encryption, decryption, and data-hiding activities in `secure_operations.log`, tracking secure operations and supporting accountability, troubleshooting, and auditing.

## Table of Contents

- [Installation](#installation)
- [Project Structure](#project-structure)
- [Packages Used](#packages-used)
- [Functionality and Algorithms](#functionality-and-algorithms)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Data-Security-using-Cryptography-and-Steganography.git
   cd Data-Security-using-Cryptography-and-Steganography

2. Install the required packages :
    ```bash
    pip install -r requirements.txt

## Project Structure

- `main.py`: Orchestrates encryption, decryption, and steganography tasks.
- `lib/`: Contains modules for cryptographic and steganographic functionality.
  - `Crypt.py`: General encryption/decryption functions for symmetric (AES, TripleDES) and asymmetric (RSA) encryption.
  - `RSA.py`: RSA-specific functions, including key generation and encryption/decryption.
  - `Secure.py`: Implements steganography for embedding/extracting data within images.
- `requirements.txt`: Lists Python dependencies for the project.
- `secure_operations.log`: Log file for secure operation tracking.
- `mydata.txt`: Example data file for testing encryption and steganography.

## Packages Used

- `rsa`: Enables RSA encryption and decryption, allowing secure key generation and asymmetric data encryption.
- `pycrypto`: Cryptographic library supporting symmetric encryption (AES, TripleDES), essential for data encryption and decryption.
- `opencv-python`: Used for image processing in steganography, allowing data to be embedded and extracted from images.
- `logging`: Python’s built-in module for operation tracking, creating a log file to facilitate auditing and troubleshooting.

## Functionality and Algorithms

### Data Encryption and Decryption

The project’s core is data encryption, making content unreadable to unauthorized users. This tool includes three main encryption algorithms, each selected for specific advantages:

#### RSA (Rivest–Shamir–Adleman)

- **Type**: Asymmetric Encryption
- **Description**: RSA uses a pair of keys: a public key for encryption and a private key for decryption. This allows data encrypted with the public key to be decrypted only with the private key, and vice versa.
- **Advantages**:
  - Ideal for Secure Data Sharing: RSA is often used when data is sent over unsecured channels, as only the private key owner can decrypt it.
  - Simplified Key Sharing: As a public-key algorithm, RSA eliminates the need for secure key sharing beforehand.
- **Use Case in Project**: RSA is useful for encrypting data for specific recipients, ensuring confidentiality as only the private key owner can decrypt the data.

#### AES (Advanced Encryption Standard)

- **Type**: Symmetric Encryption
- **Description**: AES encrypts and decrypts data with the same key, known for high security and efficiency. AES is commonly used for secure storage and data transmission.
- **Advantages**:
  - High Security and Performance: AES is a top choice for symmetric encryption, balancing security and speed for both small and large datasets.
  - Flexible Key Length: AES supports 128, 192, or 256-bit keys, allowing different security levels.
- **Use Case in Project**: AES is ideal for bulk data encryption, where data needs to be securely stored or transmitted in a controlled environment.

#### TripleDES (Triple Data Encryption Standard)

- **Type**: Symmetric Encryption
- **Description**: TripleDES, or 3DES, enhances the original DES algorithm by encrypting data three times with three different keys for added security.
- **Advantages**:
  - Increased Security: The triple encryption process makes TripleDES more secure than DES and resistant to brute-force attacks.
  - Legacy Compatibility: TripleDES is compatible with systems that used DES, allowing enhanced security without requiring a complete system overhaul.
- **Use Case in Project**: TripleDES is valuable for scenarios where AES is unavailable or for compatibility with legacy encryption systems.

### Data Hiding with Steganography

Steganography conceals data within another file, making hidden data undetectable. Here, we use steganography to hide encrypted data within image files, adding an extra security layer.

#### Why Steganography:

- **Obscurity in Security**: Encryption alone makes data unreadable but visible, whereas steganography hides the data itself within a cover file, such as an image.
- **Secure Transmission**: Data embedded in an image file can be shared inconspicuously, as it appears to be a standard media file, reducing the risk of unauthorized interception.

#### Process in Project:

- **Embedding**: Encrypted data is embedded within an image file, modifying non-visible bits to preserve the image’s visual appearance.
- **Extraction**: Hidden data can later be extracted and decrypted by authorized users.

This approach ensures confidentiality (through encryption) and obscurity (through steganography), maximizing security for sensitive information.

## Logging of Security Operations

To ensure traceability and accountability, the project logs all security operations in `secure_operations.log`.

#### Purpose of Logging:

- **Accountability**: Logs provide a record of encryption, decryption, and data-hiding activities, essential for tracking data access and modifications.
- **Troubleshooting and Audits**: Operation logs allow for easier troubleshooting and support security audits by maintaining a transparent history of secure operations.

#### Logged Information:

- **Encryption and Decryption**: Records details of encryption and decryption operations, including the type of encryption used and timestamp.
- **Data Embedding and Extraction**: Logs data hiding and extraction activities, specifying image files used and operation status.

