# PlainPHPArgon2d Library User Manual

## General information

The PlainPHPArgon2d library allows Argon2d hashes to be calculated on any standard installation of PHP7+ without the need to install any external extensions. 
The calculation of Argon2d hashes is implemented directly in PHP according to the [Argon2-RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) and uses only the arithmetic operations provided by PHP to calculate the hash.

This library was developed as part of a bachelor thesis.
You can find more about it in the corresponding [blog article](https://identeco.de/en/blog/schutz_vor_identitätsdiebstählen_durch_die_erweiterung_von_php_um_die_speicherintensive_hashfunktion_argon2d/).

## Limitations

**Due to PHP's limitations, the PlainPHPArgon2d library cannot efficiently compute Argon2d hashes. Furthermore, it is unable to safely delete the allocated memory, making the library vulnerable to [garbage collector attacks](https://eprint.iacr.org/2014/881.pdf).
Consequently, this library should NOT be used for password hashing.**

## System requirements

- At least PHP 7.4
- 64-Bit PHP

## Installation

In order to calculate Argon2d hashes with the PlainPHPArgon2d library, it must be added to the source code of the project and then the *PlainArgon2d.php* file must be included.

```bash
# Step 1: Download the PlainPHPArgon2d library
git clone https://github.com/Identeco/PlainPHPArgon2d.git

# Step 2: Add the library to the project
cp -r PlainPHPArgon2d /path/to/project

# Step 3: Include the PlainPHPArgon2d.php file
include_once("path/to/PlainArgon2d.php");
```

## Usage

### Constants
The following constants can be passed:

```php
VERSION_13 # Use version 1.3 of Argon2d
VERSION_10 # Use version 1.0 of Argon2d
DEFAULT_VALUE # Use the default values 
```

### Low-Level Function 
The *argon2d_raw_hash()* method is a low-level function that computes an Argon2d hash. 
All parameters are flexible as long as they are within the allowed value range (see [Argon2-RFC 9106](https://dl.acm.org/doi/pdf/10.17487/RFC9106)). 
If insecure parameters are used (see [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)), an **E_USER_NOTICE** is raised.
The hash is returned in decimal encoding.
If an error occurs, an exception is thrown.

```php
argon2d_raw_hash(String $password, String $salt, int $memory = 65536, int $iterations = 3,  int $parallelism = 4, int $tag_length = 32, int $version = 0x13, String $secret_key = NULL, String $assoziated_data = NULL): String
```

### Example website for the calculation of Argon2d hashes    
The following code shows how to start the attached example website for calculating Argon2d hashes. 

```bash
# Step 1: Start the local PHP web server 
cd website_example
php -S 127.0.0.1:8080

# Step 2: Open the website in the web browser 
firefox http://127.0.0.1:8080/hash-calculation.php
```

### Example for the Identeco Credential Check  
The following example code shows how the PlainPHPArgon2d library can be used to calculate the Argon2d hash of the user name for the  [Identeco Credential Check](https://identeco.de/de/products/credential-check/):

```php
// Include the class for the Argon2d calculation
include_once("path/to/PlainArgon2d.php");

// Disables warning due to low cost parameters when calculating an Argon2d hash
error_reporting(E_ALL & ~E_USER_NOTICE);

public function get_argon2d_username(String $username):String
{
    // Initialise Argon2d object 
    $argon2d = new PlainArgon2d();
    
    // Calculate the Argon2d hash of the username with a static salt and given cost parameters 
    return $argon2d->argon2d_raw_hash($username, "StaticSalt", 512, 1, 1, 16);
}
```
