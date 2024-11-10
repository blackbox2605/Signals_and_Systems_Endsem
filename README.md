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
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Packages Used](#packages-used)
- [Functionality and Algorithms](#functionality-and-algorithms)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Data-Security-using-Cryptography-and-Steganography.git
   cd Data-Security-using-Cryptography-and-Steganography

2. Install the required packages :
    ```bash
    pip install -r requirements.txt

## Usage

Run the main script:
```bash
python main.py

## Project Structure 



    
